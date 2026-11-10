#!/usr/bin/env python3
"""Compare a YandexCLI manifest against files present in the local download tree.

The manifest stores original Yandex paths. This tool reproduces the Windows
filename sanitization and collision handling used by YandexCLI.py
so renamed local files are matched to their original remote entries correctly.

Examples:
    python YandexAudit.py -d .
    python YandexAudit.py -d . --manifest .yandexcli-manifest-0123456789abcdef.json
    python YandexAudit.py -d . --root ".\\Games Archive"
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime


_WINDOWS_INVALID_CHARS = set('<>:"/\\|?*')
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
    "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
}


def sanitize_windows_component(name, max_length=240):
    """Match the filename sanitization in the current Yandex downloader."""
    original = str(name)
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


def append_collision_suffix(component, original, digest_length=8, max_length=240):
    """Match the deterministic collision suffix used by the downloader."""
    root, extension = os.path.splitext(component)
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
    suffix = "~" + digest[:digest_length]
    room = max(1, max_length - len(extension) - len(suffix))
    return root[:room] + suffix + extension


def load_manifest(download_location, explicit_manifest=None):
    if explicit_manifest:
        path = os.path.abspath(explicit_manifest)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Manifest not found: {path}")
    else:
        matches = sorted(
            os.path.join(download_location, name)
            for name in os.listdir(download_location)
            if name.startswith(".yandexcli-manifest-") and name.endswith(".json")
        )
        if not matches:
            raise FileNotFoundError(
                f"No .yandexcli-manifest-*.json found in: {download_location}"
            )
        if len(matches) > 1:
            names = "\n  ".join(os.path.basename(path) for path in matches)
            raise RuntimeError(
                "Found multiple manifests. Specify the correct one with --manifest:\n  "
                + names
            )
        path = matches[0]

    with open(path, "r", encoding="utf-8-sig") as file:
        manifest = json.load(file)

    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("Manifest has no valid 'files' list.")

    return path, manifest


def make_local_relative_paths(files):
    """Recreate the downloader's sanitized/collision-safe relative file paths."""
    validated_parts = {}
    names_by_parent = {}

    for item in files:
        if not isinstance(item, dict):
            raise ValueError("Manifest contains a non-object file entry.")

        remote_path = item.get("remote_path")
        if not isinstance(remote_path, str) or not remote_path.startswith("/"):
            raise ValueError(f"Invalid remote_path in manifest: {remote_path!r}")

        parts = remote_path.lstrip("/").split("/")
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise ValueError(f"Unsafe remote_path in manifest: {remote_path!r}")

        validated_parts[remote_path] = parts
        parent = ()
        for part in parts:
            names_by_parent.setdefault(parent, set()).add(part)
            parent = parent + (part,)

    component_map = {}
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
                local_name = append_collision_suffix(
                    base_name, remote_name, digest_length=digest_length
                )
                while (
                    local_name.casefold() in used_local_keys
                    or local_name.casefold() in reserved_base_keys
                ):
                    digest_length += 2
                    if digest_length > 64:
                        raise ValueError(
                            "Could not disambiguate colliding Windows filenames."
                        )
                    local_name = append_collision_suffix(
                        base_name, remote_name, digest_length=digest_length
                    )
            else:
                local_name = base_name

            component_map[(parent, remote_name)] = local_name
            used_local_keys.add(local_name.casefold())

    result = {}
    for remote_path, parts in validated_parts.items():
        local_parts = []
        parent = ()
        for part in parts:
            local_parts.append(component_map[(parent, part)])
            parent = parent + (part,)
        result[remote_path] = "/".join(local_parts)

    return result


def canonical_relative(path):
    """Normalize relative paths for Windows-style, case-insensitive matching."""
    return path.replace("\\", "/").strip("/").casefold()


def scan_files(root):
    actual = {}
    partials = []

    for current_dir, dirs, filenames in os.walk(root):
        # Do not follow directory symlinks; they can escape the selected tree or
        # cause loops. Normal directories are still traversed recursively.
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(current_dir, d)))

        for filename in filenames:
            full_path = os.path.join(current_dir, filename)
            rel_path = os.path.relpath(full_path, root).replace(os.sep, "/")
            if filename.lower().endswith(".part"):
                partials.append(rel_path)
                continue
            actual[canonical_relative(rel_path)] = rel_path

    return actual, sorted(partials, key=str.casefold)


def write_report(report_path, summary, missing, extra, partials, renamed):
    lines = [
        "Yandex archive audit",
        "=" * 72,
        f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Manifest: {summary['manifest_path']}",
        f"Download folder: {summary['root_path']}",
        "",
        f"Manifest entries: {summary['manifest_count']}",
        f"Files found:      {summary['actual_count']}",
        f"Present:          {summary['present_count']}",
        f"Missing:          {len(missing)}",
        f"Extra:            {len(extra)}",
        f"Partial (.part):  {len(partials)}",
        f"Renamed for Windows compatibility: {len(renamed)}",
        "",
        "MISSING FILES (listed in manifest, not found locally)",
        "-" * 72,
    ]
    lines.extend(missing or ["(none)"])
    lines += ["", "EXTRA FILES (found locally, not listed in manifest)", "-" * 72]
    lines.extend(extra or ["(none)"])
    lines += ["", "PARTIAL FILES (.part)", "-" * 72]
    lines.extend(partials or ["(none)"])
    lines += ["", "PATHS RENAMED FOR WINDOWS COMPATIBILITY", "-" * 72]
    lines.extend(
        f"{remote}  ->  {local}"
        for remote, local in renamed
    )
    if not renamed:
        lines.append("(none)")

    with open(report_path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Compare a YandexCLI manifest with files in the local download folder."
    )
    parser.add_argument(
        "-d", "--download-location", default=".",
        help="Directory passed to YandexCLI's -d option (default: current directory)."
    )
    parser.add_argument(
        "--manifest", help="Explicit manifest path; otherwise auto-detected."
    )
    parser.add_argument(
        "--root", help="Override the local archive folder (default: manifest root name)."
    )
    parser.add_argument(
        "--report", help="Report output path (default: YandexAudit-report.txt in -d)."
    )
    args = parser.parse_args()

    download_location = os.path.abspath(args.download_location)
    if not os.path.isdir(download_location):
        parser.error(f"Download location is not a directory: {download_location}")

    try:
        manifest_path, manifest = load_manifest(download_location, args.manifest)
        root_type = manifest.get("root_type")
        root_name = manifest.get("root_name") or "yandex_download"
        local_root_name = sanitize_windows_component(root_name)
        root_path = os.path.abspath(args.root or os.path.join(download_location, local_root_name))

        files = manifest["files"]
        if root_type == "file":
            # The downloader stores a single-file manifest with remote_path=null.
            if not files:
                expected_rel = os.path.basename(root_path)
                manifest_count = 1
                manifest_single_file = True
            else:
                manifest_count = len(files)
                manifest_single_file = True
                expected_rel = os.path.basename(root_path)
        elif root_type == "dir":
            manifest_count = len(files)
            manifest_single_file = False
        else:
            raise ValueError(f"Unknown manifest root_type: {root_type!r}")

        if not os.path.isdir(root_path) and not (manifest_single_file and os.path.isfile(root_path)):
            raise FileNotFoundError(f"Local download folder not found: {root_path}")

        if manifest_single_file:
            actual = {canonical_relative(expected_rel): expected_rel} if os.path.isfile(root_path) else {}
            partials = []
            expected_map = {"__single_file__": expected_rel}
        else:
            local_rel_by_remote = make_local_relative_paths(files)
            expected_map = local_rel_by_remote
            actual, partials = scan_files(root_path)

        expected_by_key = {}
        for remote_path, local_rel in expected_map.items():
            key = canonical_relative(local_rel)
            if key in expected_by_key:
                raise ValueError(
                    "Two manifest entries resolve to the same local path: "
                    f"{expected_by_key[key]} and {remote_path} -> {local_rel}"
                )
            expected_by_key[key] = remote_path

        missing = sorted(
            (expected_map[remote] for remote in expected_map
             if canonical_relative(expected_map[remote]) not in actual),
            key=str.casefold,
        )
        extra = sorted(
            (path for key, path in actual.items() if key not in expected_by_key),
            key=str.casefold,
        )
        present_count = manifest_count - len(missing)

        renamed = []
        if not manifest_single_file:
            for remote_path, local_rel in expected_map.items():
                original_rel = remote_path.lstrip("/")
                if local_rel != original_rel:
                    renamed.append((remote_path, local_rel))
        renamed.sort(key=lambda pair: pair[0].casefold())

        summary = {
            "manifest_path": manifest_path,
            "root_path": root_path,
            "manifest_count": manifest_count,
            "actual_count": len(actual),
            "present_count": present_count,
        }

        report_path = os.path.abspath(
            args.report or os.path.join(download_location, "YandexAudit-report.txt")
        )
        write_report(report_path, summary, missing, extra, partials, renamed)

        print("\n========== AUDIT SUMMARY ==========")
        print(f"Manifest entries: {manifest_count}")
        print(f"Files found:      {len(actual)}")
        print(f"Present:          {present_count}")
        print(f"Missing:          {len(missing)}")
        print(f"Extra:            {len(extra)}")
        print(f"Partial (.part):  {len(partials)}")
        print(f"Windows-renamed:  {len(renamed)}")
        print("===================================")
        print(f"\nFull report: {report_path}")

        def show_sample(label, entries, limit=20):
            if not entries:
                return
            print(f"\n{label} (showing up to {limit}):")
            for entry in entries[:limit]:
                print(f"  {entry}")
            if len(entries) > limit:
                print(f"  ... and {len(entries) - limit} more (see report)")

        show_sample("Missing files", missing)
        show_sample("Extra local files", extra)
        show_sample("Partial downloads", partials)

        return 0

    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
