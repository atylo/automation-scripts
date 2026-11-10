import argparse
from datetime import datetime
import hashlib
import json
import os
import posixpath
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import quote

import requests


ERROR_PREVIEW_LENGTH = 52


def short_error(error):
    """Return a short, descriptive error; unwrap retry wrappers when possible."""
    # Keep the complete exception chain: the outer RuntimeError often only says
    # "Download failed after 5 attempts", while __cause__ contains the real cause.
    chain = []
    seen = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )

    messages = [str(item).strip() for item in chain if str(item).strip()]
    combined = " | ".join(messages).lower()

    # If both URL-generation APIs failed, retain that context and expose the
    # status from the underlying REST/API exception where available.
    both_url_apis_failed = "both download url methods failed" in combined

    status_code = None
    reason = None
    for item in chain:
        response = getattr(item, "response", None)
        candidate = getattr(response, "status_code", None)
        if candidate is not None:
            status_code = candidate
            reason = getattr(response, "reason", None)
            break

    status_descriptions = {
        400: "bad request",
        401: "unauthorized",
        403: "forbidden",
        404: "not found",
        408: "request timeout",
        409: "conflict",
        413: "too large",
        415: "unsupported media type",
        422: "invalid request",
        425: "retry later",
        429: "rate limited",
        500: "server error",
        502: "bad gateway",
        503: "service unavailable",
        504: "gateway timeout",
    }

    if status_code is not None:
        description = status_descriptions.get(status_code)
        if description is None and reason:
            description = str(reason).strip().lower()
        if not description:
            description = "HTTP error"
        if both_url_apis_failed:
            result = f"URL APIs failed (HTTP {status_code})"
        else:
            result = f"HTTP {status_code}: {description}"
        return result[:ERROR_PREVIEW_LENGTH]

    # Match specific data/integrity failures before generic connection errors.
    if "md5 checksum mismatch" in combined:
        return "MD5 checksum mismatch"
    if "incomplete download" in combined or "size mismatch" in combined:
        return "Downloaded file size mismatch"
    if "no download url" in combined or "did not return a url" in combined:
        return "Yandex returned no download URL"
    if "invalid json" in combined or "unreadable response" in combined:
        return "Invalid response from Yandex"
    if "remote end closed connection" in combined or "remotedisconnected" in combined:
        return "Server closed the connection"
    if "connection reset by peer" in combined:
        return "Connection reset by server"
    if "connection aborted" in combined:
        return "Connection aborted"
    if "read timed out" in combined:
        return "Download read timed out"
    if "connecttimeout" in combined or "connection timed out" in combined:
        return "Connection timed out"
    if "name or service not known" in combined or "nameresolutionerror" in combined or "getaddrinfo failed" in combined:
        return "DNS lookup failed"
    if "failed to establish a new connection" in combined or "newconnectionerror" in combined:
        return "Could not connect to server"
    if "sslerror" in combined or "certificate verify failed" in combined:
        return "TLS/SSL connection error"
    if "permission denied" in combined:
        return "Local file permission denied"
    if "no space left on device" in combined:
        return "Insufficient disk space"

    # Avoid showing the generic outer retry wrapper when an inner exception is
    # available. Otherwise clean and bound the most informative message.
    candidate = next(
        (message for message in messages
         if not message.lower().startswith("download failed after ")),
        messages[0] if messages else error.__class__.__name__,
    )
    candidate = candidate.split(";", 1)[0].splitlines()[0].strip()
    candidate = re.sub(r"\s+", " ", candidate)
    if len(candidate) > ERROR_PREVIEW_LENGTH:
        candidate = candidate[:ERROR_PREVIEW_LENGTH - 3].rstrip() + "..."
    return candidate or error.__class__.__name__


class DownloadCancelled(Exception):
    """Raised internally when the user requests cancellation."""


class AggregateRateLimiter:
    """Approximate aggregate download/write rate limiter shared by workers."""

    def __init__(self, bytes_per_second, stop_event):
        self.bytes_per_second = max(0, int(bytes_per_second))
        self.stop_event = stop_event
        self.next_available = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, byte_count):
        if self.bytes_per_second <= 0 or byte_count <= 0:
            return

        with self.lock:
            now = time.monotonic()
            start_at = max(now, self.next_available)
            self.next_available = start_at + (byte_count / self.bytes_per_second)
            delay = start_at - now

        if delay > 0 and self.stop_event.wait(delay):
            raise DownloadCancelled()


def parse_rate(value):
    """Parse rates such as 20M, 512K, 1G, or 0 (unlimited)."""
    text = str(value).strip().upper()
    if not text:
        raise argparse.ArgumentTypeError("rate cannot be empty")

    multiplier = 1
    suffixes = (("GIB", 1024 ** 3), ("GB", 1000 ** 3),
                ("G", 1024 ** 3), ("MIB", 1024 ** 2),
                ("MB", 1000 ** 2), ("M", 1024 ** 2),
                ("KIB", 1024), ("KB", 1000), ("K", 1024),
                ("B", 1))
    for suffix, factor in suffixes:
        if text.endswith(suffix):
            text = text[:-len(suffix)].strip()
            multiplier = factor
            break

    try:
        number = float(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("use a value such as 20M, 512K, or 0") from error

    if number < 0:
        raise argparse.ArgumentTypeError("rate cannot be negative")

    return int(number * multiplier)


_WINDOWS_INVALID_CHARS = set('<>:"/\\|?*')
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
    "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
}


def sanitize_windows_component(name, max_length=240):
    """Make one remote path component safe for ordinary Windows filenames.

    The remote path is never changed; this function is used only to construct
    its local destination. Colons become " - " for readability, while other
    forbidden/control characters become underscores.
    """
    original = str(name)
    # Replace the colon and any adjacent whitespace as one readable separator.
    normalized = re.sub(r"\s*:\s*", " - ", original)
    cleaned_chars = []
    for char in normalized:
        codepoint = ord(char)
        if char in _WINDOWS_INVALID_CHARS or codepoint < 32:
            cleaned_chars.append("_")
        else:
            cleaned_chars.append(char)

    cleaned = "".join(cleaned_chars).rstrip(" .")
    if not cleaned or cleaned in (".", ".."):
        cleaned = "_"

    # Windows reserves device names even when an extension is present:
    # CON.txt, NUL.zip, COM1.swf, etc.
    basename = cleaned.split(".", 1)[0].rstrip(" .").upper()
    if basename in _WINDOWS_RESERVED_NAMES:
        cleaned = "_" + cleaned

    if len(cleaned) > max_length:
        root, extension = os.path.splitext(cleaned)
        suffix = "~" + hashlib.sha256(original.encode("utf-8")).hexdigest()[:8]
        room = max(1, max_length - len(extension) - len(suffix))
        cleaned = root[:room] + suffix + extension
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length]

    return cleaned


def _append_collision_suffix(component, original, digest_length=8, max_length=240):
    """Add a deterministic suffix when two remote names map to one local name."""
    root, extension = os.path.splitext(component)
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
    suffix = "~" + digest[:digest_length]
    room = max(1, max_length - len(extension) - len(suffix))
    return root[:room] + suffix + extension


class StorePrefetchParser(HTMLParser):
    """Extract the contents of Yandex's <script id="store-prefetch"> element."""

    def __init__(self):
        super().__init__()
        self._inside_script = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            attributes = dict(attrs)
            if attributes.get("id") == "store-prefetch":
                self._inside_script = True

    def handle_data(self, data):
        if self._inside_script:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._inside_script:
            self._inside_script = False


class YandexDiskDownloader:
    API_RESOURCES = "https://cloud-api.yandex.net/v1/disk/public/resources"
    API_DOWNLOAD = "https://cloud-api.yandex.net/v1/disk/public/resources/download"
    WEB_DOWNLOAD = "https://disk.yandex.ru/public/api/download-url"
    DISK_ORIGIN = "https://disk.yandex.ru"

    RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
    MAX_ATTEMPTS = 2
    MANIFEST_VERSION = 1

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) "
        "Gecko/20100101 Firefox/159.0"
    )

    def __init__(self, link, download_location, workers=4, force=False,
                 limit_rate=20 * 1024 * 1024, retry_failed=False):
        self.link = link
        self.download_location = download_location
        self.workers = workers
        self.force = force
        self.limit_rate = limit_rate
        self.retry_failed = retry_failed
        self.refresh_list = False

        self.stop_event = threading.Event()
        self.thread_local = threading.local()
        self.print_lock = threading.Lock()
        self.hash_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.rate_limiter = AggregateRateLimiter(limit_rate, self.stop_event)
        self.local_state = {"version": 1, "public_key": None,
                            "verified": {}, "failed": {}}
        self.state_updates = 0
        self.state_save_every = 16

        self.public_key = None
        self.sk = None
        self.share_page_url = link
        self.base_cookies = None
        self.root_resource_hash = None
        self.web_api_available = False

    def _log(self, message):
        with self.print_lock:
            print(message, flush=True)

    def _get_session(self):
        """Return one requests.Session per thread, seeded with share-page cookies."""
        if not hasattr(self.thread_local, "session"):
            session = requests.Session()
            session.headers.update({
                "User-Agent": self.USER_AGENT,
                "Accept-Language": "en-US,en;q=0.5",
            })

            # Copy cookies obtained from the public share page. These are acquired
            # automatically; no browser cookies or account credentials are needed.
            if self.base_cookies is not None:
                session.cookies.update(self.base_cookies)

            self.thread_local.session = session

        return self.thread_local.session

    @staticmethod
    def _response_error(message, status_code=500):
        """Create an HTTPError carrying a status code for retry classification."""
        response = requests.Response()
        response.status_code = status_code
        response._content = message.encode("utf-8", errors="replace")
        return requests.HTTPError(message, response=response)

    def _api_request(self, url, params):
        response = self._get_session().get(
            url,
            params=params,
            timeout=(10, 20)
        )

        try:
            data = response.json()
        except ValueError:
            response.raise_for_status()
            raise requests.ConnectionError(
                "Yandex returned invalid JSON: " + response.text[:1000]
            )

        if not response.ok:
            raise requests.HTTPError(
                f"Yandex API error (HTTP {response.status_code}): {data}",
                response=response
            )

        return data

    def _get_metadata(self, path=None):
        params = {"public_key": self.link}
        if path is not None:
            params["path"] = path
        return self._api_request(self.API_RESOURCES, params)

    def _initialize_web_api(self):
        """Load the public share page and obtain its current `environment.sk`."""
        session = self._get_session()
        response = session.get(
            self.link,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": self.DISK_ORIGIN + "/",
            },
            timeout=(10, 20),
        )
        response.raise_for_status()
        self.share_page_url = response.url

        parser = StorePrefetchParser()
        parser.feed(response.text)
        prefetch_text = "".join(parser.parts).strip()

        # Fallback in case the page's script markup confuses HTMLParser.
        if not prefetch_text:
            match = re.search(
                r'<script\b[^>]*\bid=["\']store-prefetch["\'][^>]*>(.*?)</script\s*>',
                response.text,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if match:
                prefetch_text = match.group(1).strip()

        if not prefetch_text:
            raise RuntimeError(
                "Could not find script#store-prefetch in the public share page."
            )

        try:
            prefetch = json.loads(prefetch_text)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "Could not parse Yandex's store-prefetch JSON."
            ) from error

        environment = prefetch.get("environment") or {}
        self.sk = environment.get("sk")

        # A shared single-file link may expose its exact hash here. Folder items
        # use public_key + ':' + their metadata path, as in the browser request.
        resources = prefetch.get("resources") or {}
        if isinstance(resources, dict):
            for resource in resources.values():
                if isinstance(resource, dict) and resource.get("hash"):
                    self.root_resource_hash = resource["hash"]
                    break

        if not self.sk:
            raise RuntimeError(
                "Yandex's public page did not contain environment.sk."
            )

        # Save a cookie-jar copy for worker sessions created by the thread pool.
        self.base_cookies = session.cookies.copy()
        self.web_api_available = True

    def _list_directory(self, path=None):
        offset = 0
        limit = 100

        while not self.stop_event.is_set():
            params = {
                "public_key": self.link,
                "limit": limit,
                "offset": offset,
            }
            if path is not None:
                params["path"] = path

            data = self._api_request(self.API_RESOURCES, params)
            embedded = data.get("_embedded", {})
            items = embedded.get("items", [])

            if not items:
                break

            for item in items:
                yield item

            offset += len(items)
            total = embedded.get("total", offset)
            if offset >= total:
                break

    def _collect_files(self, remote_path, files):
        """Recursively enumerate remote files without downloading their contents."""
        if self.stop_event.is_set():
            return

        for item in self._list_directory(remote_path):
            if self.stop_event.is_set():
                return

            item_path = item["path"]
            item_type = item["type"]

            if item_type == "dir":
                self._collect_files(item_path, files)
            elif item_type == "file":
                files.append({
                    "remote_path": item_path,
                    "size": item.get("size"),
                    "md5": item.get("md5"),
                })

    def _manifest_path(self):
        """Return a per-public-resource manifest path beside the download root."""
        identity = self.public_key or self.link
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return os.path.join(
            self.download_location,
            f".yandexcli-manifest-{digest}.json",
        )

    def _state_path(self):
        """Return the per-share resume-state path beside the download root."""
        identity = self.public_key or self.link
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return os.path.join(
            self.download_location,
            f".yandexcli-state-{digest}.json",
        )

    def _failed_log_path(self):
        """Return a readable list of files deferred after previous failures."""
        identity = self.public_key or self.link
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return os.path.join(
            self.download_location,
            f".yandexcli-failed-{digest}.txt",
        )

    @staticmethod
    def _state_key(remote_path):
        return remote_path if remote_path is not None else "__single_file__"

    @staticmethod
    def _remote_size(value):
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _save_state_locked(self):
        """Atomically persist local verification cache and failed-file ledger."""
        state_path = self._state_path()
        temp_path = state_path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as file:
                json.dump(self.local_state, file, ensure_ascii=False, indent=2)
                file.flush()
            os.replace(temp_path, state_path)

            # Keep a simple text file for quick inspection. The JSON state is
            # authoritative; this text file is a human-readable companion.
            failed_path = self._failed_log_path()
            failed_temp = failed_path + ".tmp"
            with open(failed_temp, "w", encoding="utf-8") as file:
                for remote_path, details in sorted(
                    self.local_state.get("failed", {}).items()
                ):
                    if remote_path == "__single_file__":
                        display_path = "<single file>"
                    else:
                        display_path = remote_path
                    file.write(
                        f"{display_path}\t{details.get('failed_at', '')}\t"
                        f"{details.get('error', '')}\n"
                    )
            os.replace(failed_temp, failed_path)
            self.state_updates = 0
        except OSError as error:
            for leftover in (temp_path, self._failed_log_path() + ".tmp"):
                if os.path.exists(leftover):
                    try:
                        os.remove(leftover)
                    except OSError:
                        pass
            self._log(f"[WARN] Resume state not saved: {short_error(error)}")

    def _load_state(self):
        """Load cached local verification and failures for this public resource."""
        state_path = self._state_path()
        if os.path.isfile(state_path):
            try:
                with open(state_path, "r", encoding="utf-8") as file:
                    saved = json.load(file)
                if (saved.get("version") == 1
                        and saved.get("public_key") == self.public_key
                        and isinstance(saved.get("verified", {}), dict)
                        and isinstance(saved.get("failed", {}), dict)):
                    self.local_state = {
                        "version": 1,
                        "public_key": self.public_key,
                        "verified": saved.get("verified", {}),
                        "failed": saved.get("failed", {}),
                    }
                    self._log(
                        f"[STATE] Loaded {len(self.local_state['verified'])} local checks "
                        f"and {len(self.local_state['failed'])} previous failures."
                    )
                else:
                    self._log("[STATE] Ignoring incompatible resume-state file.")
            except (OSError, json.JSONDecodeError, AttributeError, TypeError) as error:
                self._log(f"[STATE] Ignoring unreadable resume state: {short_error(error)}")

        self.local_state["public_key"] = self.public_key

        if self.retry_failed and self.local_state["failed"]:
            count = len(self.local_state["failed"])
            self.local_state["failed"].clear()
            with self.state_lock:
                self._save_state_locked()
            self._log(f"[STATE] Cleared {count} previous failures for retry.")

    def _state_changed(self, force_save=False):
        with self.state_lock:
            self.state_updates += 1
            if force_save or self.state_updates >= self.state_save_every:
                self._save_state_locked()

    def _verified_in_state(self, item, local_path):
        """Check whether an unchanged local file was already MD5-verified."""
        key = self._state_key(item.get("remote_path"))
        with self.state_lock:
            record = self.local_state["verified"].get(key)
            if not isinstance(record, dict):
                return False

        try:
            stat = os.stat(local_path)
        except OSError:
            return False

        expected_size = self._remote_size(item.get("size"))
        expected_md5 = self._normalize_md5(item.get("md5"))

        return (
            record.get("local_size") == stat.st_size
            and record.get("local_mtime_ns") == stat.st_mtime_ns
            and record.get("remote_size") == expected_size
            and record.get("remote_md5") == expected_md5
        )

    def _remember_verified(self, item, local_path):
        """Remember a successful verification so later resumes avoid rereading it."""
        try:
            stat = os.stat(local_path)
        except OSError:
            return

        key = self._state_key(item.get("remote_path"))
        record = {
            "local_size": stat.st_size,
            "local_mtime_ns": stat.st_mtime_ns,
            "remote_size": self._remote_size(item.get("size")),
            "remote_md5": self._normalize_md5(item.get("md5")),
        }
        with self.state_lock:
            self.local_state["verified"][key] = record
            self.local_state["failed"].pop(key, None)
        self._state_changed()

    def _record_failure(self, item, error):
        key = self._state_key(item.get("remote_path"))
        record = {
            "remote_size": self._remote_size(item.get("size")),
            "remote_md5": self._normalize_md5(item.get("md5")),
            "failed_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "error": short_error(error),
        }
        with self.state_lock:
            self.local_state["failed"][key] = record
        self._state_changed(force_save=True)

    def _clear_failure(self, remote_path):
        key = self._state_key(remote_path)
        changed = False
        with self.state_lock:
            if key in self.local_state["failed"]:
                del self.local_state["failed"][key]
                changed = True
        if changed:
            self._state_changed(force_save=True)

    def _is_previously_failed(self, item):
        key = self._state_key(item.get("remote_path"))
        with self.state_lock:
            record = self.local_state["failed"].get(key)
            if not isinstance(record, dict):
                return False

        # Only suppress the same remote version. A changed size or MD5 is a new
        # version and should be attempted even without --retry-failed.
        return (
            record.get("remote_size") == self._remote_size(item.get("size"))
            and record.get("remote_md5") == self._normalize_md5(item.get("md5"))
        )

    def _load_manifest(self, metadata):
        """Load a cached file listing if it belongs to this exact root resource."""
        manifest_path = self._manifest_path()

        if not os.path.isfile(manifest_path):
            return None

        try:
            with open(manifest_path, "r", encoding="utf-8") as file:
                manifest = json.load(file)

            if manifest.get("version") != self.MANIFEST_VERSION:
                raise ValueError("unsupported manifest version")
            if manifest.get("public_key") != self.public_key:
                raise ValueError("manifest belongs to another public resource")
            if manifest.get("root_type") != metadata.get("type"):
                raise ValueError("resource type changed")
            if manifest.get("root_name") != metadata.get("name"):
                raise ValueError("resource name changed")

            # If Yandex exposes a root modified timestamp, invalidate the cache
            # when it changes. The user can also force a refresh with --refresh-list.
            current_modified = metadata.get("modified")
            cached_modified = manifest.get("root_modified")
            if current_modified and cached_modified and current_modified != cached_modified:
                raise ValueError("remote root modification timestamp changed")

            files = manifest.get("files")
            if not isinstance(files, list):
                raise ValueError("manifest file list is invalid")

            validated = []
            for item in files:
                if not isinstance(item, dict):
                    raise ValueError("manifest contains an invalid entry")
                remote_path = item.get("remote_path")
                if metadata.get("type") == "file":
                    if remote_path is not None:
                        raise ValueError("manifest contains an invalid single-file path")
                else:
                    if not isinstance(remote_path, str) or not remote_path.startswith("/"):
                        raise ValueError("manifest contains an invalid remote path")
                    parts = remote_path.lstrip("/").split("/")
                    if any(part in ("", ".", "..") for part in parts):
                        raise ValueError("manifest contains an unsafe remote path")

                validated.append({
                    "remote_path": remote_path,
                    "size": item.get("size"),
                    "md5": item.get("md5"),
                })

            return manifest, validated

        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            self._log(
                f"[CACHE] Ignoring saved listing: {short_error(error)}"
            )
            return None

    def _save_manifest(self, metadata, files):
        """Atomically save the remote file listing for subsequent resume runs."""
        manifest_path = self._manifest_path()
        manifest = {
            "version": self.MANIFEST_VERSION,
            "public_key": self.public_key,
            "root_name": metadata.get("name"),
            "root_type": metadata.get("type"),
            "root_modified": metadata.get("modified"),
            "saved_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "files": files,
        }

        temp_path = manifest_path + ".tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as file:
                json.dump(manifest, file, ensure_ascii=False, indent=2)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp_path, manifest_path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

    def _prepare_file_entries(self, metadata, local_root, cached_files):
        """Attach Windows-safe local paths without changing remote API paths."""
        prepared = []

        if metadata.get("type") == "file":
            for item in cached_files:
                prepared.append({
                    "remote_path": item.get("remote_path"),
                    "local_path": local_root,
                    "size": item.get("size"),
                    "md5": item.get("md5"),
                })
            return prepared

        # Build a mapping of remote child names to local names at each directory
        # level. This also detects names that would collide after sanitization
        # (including Windows case-insensitive collisions) and gives them stable
        # suffixes instead of allowing one remote file to overwrite another.
        names_by_parent = {}
        validated_parts = {}
        for item in cached_files:
            remote_path = item.get("remote_path")
            if not isinstance(remote_path, str) or not remote_path.startswith("/"):
                raise ValueError("Invalid remote path in cached directory listing")

            parts = remote_path.lstrip("/").split("/")
            if any(part in ("", ".", "..") for part in parts):
                raise ValueError("Unsafe path in cached directory listing")

            validated_parts[remote_path] = parts
            parent = ()
            for part in parts:
                names_by_parent.setdefault(parent, set()).add(part)
                parent = parent + (part,)

        component_map = {}
        changed_components = 0
        for parent, remote_names in names_by_parent.items():
            base_names = {
                remote_name: sanitize_windows_component(remote_name)
                for remote_name in remote_names
            }
            counts = {}
            for base_name in base_names.values():
                key = base_name.casefold()
                counts[key] = counts.get(key, 0) + 1

            reserved_base_keys = set(counts)
            used_local_keys = set()

            for remote_name in sorted(remote_names, key=lambda value: (value.casefold(), value)):
                base_name = base_names[remote_name]
                base_key = base_name.casefold()
                needs_suffix = counts[base_key] > 1 or base_key in used_local_keys

                if needs_suffix:
                    digest_length = 8
                    local_name = _append_collision_suffix(
                        base_name, remote_name, digest_length=digest_length
                    )
                    while (
                        local_name.casefold() in used_local_keys
                        or local_name.casefold() in reserved_base_keys
                    ):
                        digest_length += 2
                        if digest_length > 64:
                            raise ValueError("Could not disambiguate colliding Windows filenames")
                        local_name = _append_collision_suffix(
                            base_name, remote_name, digest_length=digest_length
                        )
                else:
                    local_name = base_name

                component_map[(parent, remote_name)] = local_name
                used_local_keys.add(local_name.casefold())
                if local_name != remote_name:
                    changed_components += 1

        for item in cached_files:
            remote_path = item.get("remote_path")
            parts = validated_parts[remote_path]
            local_parts = []
            parent = ()
            for part in parts:
                local_parts.append(component_map[(parent, part)])
                parent = parent + (part,)

            local_path = os.path.join(local_root, *local_parts)

            # Ensure the resolved destination remains below the download root.
            root_abs = os.path.abspath(local_root)
            target_abs = os.path.abspath(local_path)
            if os.path.commonpath((root_abs, target_abs)) != root_abs:
                raise ValueError("Cached path escapes the download directory")

            prepared.append({
                "remote_path": remote_path,
                "local_path": local_path,
                "size": item.get("size"),
                "md5": item.get("md5"),
            })

        if changed_components:
            self._log(
                f"[PATH] Sanitized {changed_components} remote path component(s) "
                "for Windows compatibility. Remote paths remain unchanged."
            )

        return prepared

    def _get_page_referer(self, remote_path):
        """Build a share-folder referer similar to the browser's request."""
        folder = posixpath.dirname(remote_path or "").strip("/")
        referer = self.share_page_url.rstrip("/")
        if folder:
            referer += "/" + quote(folder, safe="/")
        return referer

    def _get_web_download_url(self, remote_path):
        if not self.web_api_available or not self.sk:
            raise RuntimeError("The browser-style public download API is unavailable.")

        if remote_path is None and self.root_resource_hash:
            resource_hash = self.root_resource_hash
        else:
            if not self.public_key:
                raise RuntimeError("The public key is missing from resource metadata.")
            path = remote_path or ""
            resource_hash = f"{self.public_key}:{path}"

        payload = {
            "hash": resource_hash,
            "inline": False,
            "sk": self.sk,
        }
        body = json.dumps(payload, separators=(",", ":"))
        referer = self._get_page_referer(remote_path)

        headers = {
            "Accept": "*/*",
            "Content-Type": "text/plain",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": self.DISK_ORIGIN,
            "Referer": referer,
            "X-Retpath-Y": referer,
        }

        # The captured browser request sends the JSON text URL-encoded despite
        # declaring text/plain. Try that wire format first; some Yandex clients
        # and public examples use raw JSON, so fall back to raw JSON if necessary.
        encoded_body = quote(body, safe="")
        last_error = None

        for body_index, request_body in enumerate((encoded_body, body)):
            response = self._get_session().post(
                self.WEB_DOWNLOAD,
                data=request_body,
                headers=headers,
                timeout=(10, 20),
            )

            try:
                result = response.json()
            except ValueError:
                result = None

            if not response.ok:
                last_error = requests.HTTPError(
                    f"Yandex public download-url API error "
                    f"(HTTP {response.status_code}): {response.text[:1000]}",
                    response=response,
                )
                # Only try the alternate body format for likely format errors.
                if body_index == 0 and response.status_code in (400, 415, 422):
                    continue
                break

            if not isinstance(result, dict):
                last_error = requests.ConnectionError(
                    "Yandex public download-url API returned an unreadable response: "
                    + response.text[:1000]
                )
                if body_index == 0:
                    continue
                break

            error_flag = result.get("error", False)
            is_error = error_flag is True or str(error_flag).lower() == "true"
            status_code = result.get("statusCode", 200)
            data = result.get("data") or {}
            download_url = data.get("url") if isinstance(data, dict) else None

            try:
                status_code = int(status_code or 200)
            except (TypeError, ValueError):
                status_code = 500

            if not is_error and status_code == 200 and download_url:
                return download_url

            message = (
                f"Yandex public download-url API returned an error: {result}"
            )
            last_error = self._response_error(message, status_code)

            # A validation error may indicate that this Yandex deployment wants
            # raw JSON rather than the URL-encoded body (or vice versa).
            if body_index == 0 and (status_code in (200, 400, 415, 422)):
                continue
            break

        raise last_error or requests.ConnectionError(
            "Yandex public download-url API did not return a URL."
        )

    def _get_rest_download_url(self, remote_path):
        params = {"public_key": self.link}
        if remote_path is not None:
            params["path"] = remote_path

        data = self._api_request(self.API_DOWNLOAD, params)
        download_url = data.get("href")
        if not download_url:
            raise requests.ConnectionError(
                f"Yandex REST API did not return href for {remote_path}: {data}"
            )
        return download_url

    def _get_download_url(self, remote_path):
        """Prefer the web endpoint; fall back to the public REST API."""
        web_error = None

        if self.web_api_available:
            try:
                return self._get_web_download_url(remote_path), "web"
            except (requests.RequestException, RuntimeError, ValueError) as error:
                web_error = error
                self._log(
                    f"[URL FALLBACK] Browser-style URL request failed for "
                    f"{remote_path}: {short_error(error)}"
                )

        try:
            return self._get_rest_download_url(remote_path), "REST"
        except requests.RequestException as rest_error:
            if web_error is not None:
                raise requests.ConnectionError(
                    f"Both download URL methods failed for {remote_path}. "
                    f"Web endpoint: {web_error}; REST endpoint: {rest_error}"
                ) from rest_error
            raise

    @staticmethod
    def _normalize_md5(value):
        """Return a normalized 32-character MD5 value, or None if unavailable."""
        if not isinstance(value, str):
            return None

        value = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{32}", value):
            return value
        return None

    def _calculate_md5(self, file_path):
        """Calculate MD5 in a single worker, checking for cancellation per chunk."""
        digest = hashlib.md5()
        with open(file_path, "rb") as file:
            while True:
                if self.stop_event.is_set():
                    raise DownloadCancelled()
                chunk = file.read(256 * 1024)
                if not chunk:
                    break
                self.rate_limiter.consume(len(chunk))
                digest.update(chunk)
        return digest.hexdigest()

    def _download_file(self, remote_path, local_path, remote_size, remote_md5=None):
        temp_path = local_path + ".part"

        if self.stop_event.is_set():
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return "cancelled"

        try:
            expected_size = int(remote_size) if remote_size is not None else None
        except (TypeError, ValueError):
            expected_size = None

        expected_md5 = self._normalize_md5(remote_md5)

        item = {
            "remote_path": remote_path,
            "size": remote_size,
            "md5": remote_md5,
        }

        # A cached stat fingerprint avoids hashing the same unchanged file on
        # every resume. The first run still verifies its MD5 once.
        if not self.force and os.path.isfile(local_path):
            if self._verified_in_state(item, local_path):
                self._log(f"[SKIP] {remote_path} (cached verification)")
                self._clear_failure(remote_path)
                return "skipped"

            local_size = os.path.getsize(local_path)
            if expected_md5 and (expected_size is None or local_size == expected_size):
                # Serialize first-time hashes to avoid several workers flooding
                # the SSD with simultaneous full-file reads.
                try:
                    with self.hash_lock:
                        local_md5 = self._calculate_md5(local_path)
                except DownloadCancelled:
                    return "cancelled"
                if local_md5 == expected_md5:
                    self._remember_verified(item, local_path)
                    self._log(f"[SKIP] {remote_path} (MD5 OK)")
                    return "skipped"
            elif expected_size is not None and local_size == expected_size:
                self._remember_verified(item, local_path)
                self._log(f"[SKIP] {remote_path} (size only; no remote MD5)")
                return "skipped"

        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            if self.stop_event.is_set():
                return "cancelled"

            try:
                download_url, source = self._get_download_url(remote_path)
                if self.stop_event.is_set():
                    raise DownloadCancelled()

                self._log(
                    f"[DOWNLOAD] {remote_path} "
                    f"(attempt {attempt}/{self.MAX_ATTEMPTS}, URL: {source})"
                )

                download_digest = hashlib.md5() if expected_md5 else None
                with self._get_session().get(
                    download_url,
                    stream=True,
                    timeout=(10, 15),
                    headers={"Referer": self.DISK_ORIGIN + "/"},
                ) as response:
                    response.raise_for_status()

                    with open(temp_path, "wb") as file:
                        for chunk in response.iter_content(chunk_size=256 * 1024):
                            if self.stop_event.is_set():
                                raise DownloadCancelled()
                            if chunk:
                                # Apply one aggregate cap across all workers.
                                self.rate_limiter.consume(len(chunk))
                                file.write(chunk)
                                if download_digest is not None:
                                    download_digest.update(chunk)

                if self.stop_event.is_set():
                    raise DownloadCancelled()

                downloaded_size = os.path.getsize(temp_path)
                if (
                    expected_size is not None
                    and downloaded_size != expected_size
                ):
                    raise requests.ConnectionError(
                        f"Incomplete download: expected {expected_size} bytes, "
                        f"received {downloaded_size} bytes"
                    )

                # Verify the MD5 calculated from incoming chunks. This avoids
                # rereading the complete temporary file from the SSD.
                if expected_md5 and download_digest.hexdigest() != expected_md5:
                    raise requests.ConnectionError("MD5 checksum mismatch")

                if self.stop_event.is_set():
                    raise DownloadCancelled()

                os.replace(temp_path, local_path)
                self._remember_verified(item, local_path)
                self._clear_failure(remote_path)
                self._log(f"[DONE] {remote_path}")
                return "downloaded"

            except DownloadCancelled:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                return "cancelled"

            except requests.RequestException as error:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

                if self.stop_event.is_set():
                    return "cancelled"

                response = getattr(error, "response", None)
                status_code = response.status_code if response is not None else None
                retryable = (
                    status_code is None
                    or status_code in self.RETRYABLE_STATUS_CODES
                )

                if not retryable:
                    raise

                if attempt == self.MAX_ATTEMPTS:
                    raise RuntimeError(
                        f"Download failed after {self.MAX_ATTEMPTS} attempts: "
                        f"{remote_path}: {error}"
                    ) from error

                delay = min(2 ** attempt, 30)
                # All console error messages use the global short_error() formatter.
                self._log(
                    f"[RETRY] {remote_path}: {short_error(error)}\n"
                    f"Retrying in {delay} seconds..."
                )

                if self.stop_event.wait(delay):
                    return "cancelled"

            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise

        return "failed"

    def download(self):
        os.makedirs(self.download_location, exist_ok=True)

        metadata = self._get_metadata()
        self.public_key = metadata.get("public_key")
        self._load_state()

        # The public REST metadata endpoint can work even when the web page/API
        # is degraded. If the page bootstrap fails, downloads still fall back
        # to the documented REST download-link endpoint.
        try:
            self._initialize_web_api()
            self._log("[INFO] Browser-style public download endpoint initialized.")
        except (requests.RequestException, RuntimeError, ValueError) as error:
            self.web_api_available = False
            self._log(
                f"[WARN] Could not initialize browser-style endpoint: {short_error(error)}\n"
                "[WARN] Will use the public REST download endpoint instead."
            )

        name = metadata.get("name", "yandex_download")
        local_name = sanitize_windows_component(name)
        if local_name != name:
            self._log(
                f"[PATH] Sanitized root name {name!r} to {local_name!r} "
                "for Windows compatibility."
            )
        local_path = os.path.join(self.download_location, local_name)

        if metadata["type"] not in ("file", "dir"):
            raise RuntimeError(f"Unknown resource type: {metadata['type']}")

        # Reuse the saved remote directory listing by default. This avoids
        # recursively querying every folder again when resuming downloads.
        cached = None if self.refresh_list else self._load_manifest(metadata)
        if cached is not None:
            manifest, cached_files = cached
            files = self._prepare_file_entries(metadata, local_path, cached_files)
            saved_at = manifest.get("saved_at", "unknown date")
            self._log(
                f"[CACHE] Loaded {len(files)} files from saved listing ({saved_at})."
            )
        else:
            if metadata["type"] == "file":
                discovered = [{
                    "remote_path": None,
                    "size": metadata.get("size"),
                    "md5": metadata.get("md5"),
                }]
            else:
                discovered = []
                self._log("[LIST] Reading remote directory contents...")
                self._collect_files(None, discovered)

            if self.stop_event.is_set():
                self._log("[STOP] Cancelled while listing the folder.")
                raise SystemExit(130)

            # Save before starting downloads. If downloads are interrupted,
            # the next run can immediately resume using this manifest.
            self._save_manifest(metadata, discovered)
            self._log(
                f"[CACHE] Saved listing of {len(discovered)} files to "
                f"{os.path.basename(self._manifest_path())}."
            )
            files = self._prepare_file_entries(metadata, local_path, discovered)

        md5_count = sum(
            1 for item in files if self._normalize_md5(item.get("md5"))
        )
        if files and md5_count == len(files):
            self._log(f"[INFO] Yandex supplied MD5 for all {md5_count} files.")
        elif md5_count:
            self._log(
                f"[INFO] Yandex supplied MD5 for {md5_count}/{len(files)} files; "
                "the rest will use size-only checks."
            )
        else:
            self._log(
                "[INFO] No MD5 values found in file metadata; "
                "existing files will use size-only checks."
            )

        total_files = len(files)
        deferred_files = []
        candidates = []
        if not self.retry_failed:
            for item in files:
                if self._is_previously_failed(item):
                    deferred_files.append(item["remote_path"])
                else:
                    candidates.append(item)
        else:
            candidates = files

        print(f"\nFound {total_files} files.")
        print(f"Already failed (deferred): {len(deferred_files)}")
        print(f"Queued this run: {len(candidates)}")
        print(f"Concurrent downloads: {self.workers}")
        if self.limit_rate > 0:
            print(f"Aggregate I/O pacing: {self.limit_rate / (1024 * 1024):.1f} MiB/s\n")
        else:
            print("Aggregate I/O pacing: disabled\n")

        downloaded = 0
        skipped = 0
        failed = []
        executor = ThreadPoolExecutor(max_workers=self.workers)
        futures = {}

        try:
            for item in candidates:
                if self.stop_event.is_set():
                    break
                future = executor.submit(
                    self._download_file,
                    item["remote_path"],
                    item["local_path"],
                    item["size"],
                    item.get("md5"),
                )
                futures[future] = item

            for future in as_completed(futures):
                item = futures[future]
                try:
                    result = future.result()
                    if result == "downloaded":
                        downloaded += 1
                    elif result == "skipped":
                        skipped += 1
                except Exception as error:
                    failed.append(item["remote_path"])
                    self._record_failure(item, error)
                    self._log(
                        f"[ERROR] {item['remote_path']}: {short_error(error)}"
                    )

        except KeyboardInterrupt:
            self._log("\n[STOP] Cancelling queued and active downloads...")
            self.stop_event.set()
            self._state_changed(force_save=True)
            for future in futures:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            self._log(
                "[STOP] Downloader stopped. Completed files are preserved; "
                "unfinished .part files are removed."
            )
            raise SystemExit(130)

        else:
            executor.shutdown(wait=True)

        self._state_changed(force_save=True)

        print("\n========== SUMMARY ==========")
        print(f"Downloaded: {downloaded}")
        print(f"Skipped:    {skipped}")
        print(f"Failed:     {len(failed)}")
        print(f"Deferred:   {len(deferred_files)} (previous failures)")
        print("=============================")

        if failed:
            print("\nFailed files:")
            for path in failed:
                print(f"  {path}")

        return failed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Yandex Disk public-folder downloader"
    )
    parser.add_argument(
        "-l", "--link", type=str, required=True,
        help="Yandex Disk public URL"
    )
    parser.add_argument(
        "-d", "--download_location", type=str, required=True,
        help="Local download directory"
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=4,
        help="Number of simultaneous downloads (default: 4)"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Redownload files that already exist locally"
    )
    parser.add_argument(
        "--refresh-list", action="store_true",
        help="Ignore the cached directory listing and fetch it again"
    )
    parser.add_argument(
        "--retry-failed", action="store_true",
        help="Retry files recorded as failed in previous runs"
    )
    parser.add_argument(
        "--limit-rate", type=parse_rate, default=20 * 1024 * 1024,
        metavar="RATE",
        help="Approximate aggregate pacing for MD5 reads and download writes "
             "(e.g. 20M, 500K; 0 disables; default: 20M)"
    )
    args = parser.parse_args()

    if args.jobs < 1:
        parser.error("--jobs must be at least 1")

    downloader = YandexDiskDownloader(
        args.link,
        args.download_location,
        workers=args.jobs,
        force=args.force,
        limit_rate=args.limit_rate,
        retry_failed=args.retry_failed,
    )
    downloader.refresh_list = args.refresh_list

    try:
        failed = downloader.download()
        if failed:
            raise SystemExit(1)
    except KeyboardInterrupt:
        downloader.stop_event.set()
        print("\n[STOP] Interrupted.", flush=True)
        raise SystemExit(130)
    except Exception as error:
        parser.exit(1, f"\nError: {short_error(error)}\n")
