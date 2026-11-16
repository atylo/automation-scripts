import json
from urllib.parse import unquote_plus
from datetime import datetime
import requests

USER_AGENT = 'c384da2W9f73dz20403d'

CONTENT_PROPERTIES = (
    # (key, transformer).
    ('egg',               str),
    ('version',           str), # Now empty
    ('title',             str),
    ('productId',         str),
    ('publisher',         str),
    ('platform',          str),
    ('genre',             str),
    ('year',              str),
    ('mystery1',          str),  # TODO: always 0 — meaning unknown
    ('gameFilename',      str),
    ('lastUpdated',       str),  # Some sort of date...
    ('hasMusic',          lambda s: bool(int(s))),  # 0 or 1, encryption or music present...?
    ('owned',             lambda s: bool(int(s))),
    ('thumbnailFilename', str),
    ('description',       str),
    ('mystery5',          str),  # TODO: used to be always 1, now always 0
    ('manualFilename',    str),
    ('manualDate',        str),  # Only appears if the game has a manual...?
    ('musicFilename',     str),  # Only appears if the game has music...?
    ('musicDate',         str),
    ('releaseDate',       str),  # Available to purchase in the store
    ('storeExpiryDate',   str),  # Some future date...? An expiration?
    ('uploadDate',        str),  # A date - possibly the "added on" date?
    ('mystery8',          str),  # Another future date; possibly always the same as storeExpiryDate.
    ('mystery9',          str),  # 679 or 1194, probably referencing a tool or original game.
    ('region',            int),  # 0: Japanese; 1: English
    ('currentPrice',      str),
)

FIELDS_PER_ENTRY = len(CONTENT_PROPERTIES)


def get_purchased(username: str, password: str):
    print("Downloading please wait...")
    """
    Fetch the list of purchased content for a given user from the API.
    Returns a tuple of parsed entries (dicts).
    """
    try:
        r = requests.post(
            'https://api.amusement-center.com/api/dcp/v1/getcontentslist',
            headers={'User-Agent': USER_AGENT},
            data={
                'userid': username,
                'passwd': password,
            },
            timeout=10,
        )
    except requests.RequestException as e:
        raise ConnectionError(f"Network error while talking to server: {e}") from e

    if r.status_code != 200:
        raise ConnectionError(
            f"Could not get list of purchased content (HTTP {r.status_code})."
        )

    # Response format: "status,<comma-separated fields...>"
    raw = r.content.decode('ascii')
    first_comma_pos = raw.find(',')
    

    if first_comma_pos == -1:
        status = raw
        data = ""
    else:
        status = raw[:first_comma_pos]
        data = raw[first_comma_pos + 1:]

    if status != 'ok':
        raise ValueError(
            f"Could not get list of purchased content. "
            f"Server returned status '{status}'. "
            f"Login credentials may have been incorrect."
        )

    return tuple(parse_content_entries(data))


def parse_content_entries(data: str):
    print("Parsing the entries...")
    """
    Parse the comma-separated field blob into individual entries.

    The API returns one big CSV-like string (no quotes/escaping),
    where every group of FIELDS_PER_ENTRY fields is one entry.
    """

    # Split into raw fields
    fields = data.split(',')

    # Drop trailing empty fields caused by trailing commas
    while fields and fields[-1] == '':
        fields.pop()

    # If the count still isn't a multiple, truncate to nearest multiple,
    # like the original script effectively did (it would just read empty
    # strings at EOF for missing fields).
    if fields and len(fields) % FIELDS_PER_ENTRY != 0:
        valid_count = (len(fields) // FIELDS_PER_ENTRY) * FIELDS_PER_ENTRY
        # If you ever want to debug:
        # print(f"Warning: truncating {len(fields) - valid_count} leftover field(s)")
        fields = fields[:valid_count]

    it = iter(fields)
    while True:
        try:
            raw_fields = [next(it) for _ in range(FIELDS_PER_ENTRY)]
        except StopIteration:
            break
        yield parse_content_entry(raw_fields)

def decode_field(raw: str) -> str:
    decoded = unquote_plus(raw, encoding='euc_jis_2004')
    decoded = decoded.replace('\r\n', '').replace('\r', '')
    decoded = decoded.replace('，', ',')
    return decoded.strip()

def parse_content_entry(raw_fields):
    """
    Turn a flat list of raw string fields into a dict using CONTENT_PROPERTIES.
    """
    return {
        key: transformer(decode_field(field))
        for (key, transformer), field in zip(CONTENT_PROPERTIES, raw_fields)
    }


def main():
    username = 'lolcat54'
    password = 'lostmypass'

    entries = get_purchased(username, password)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"gamelist_{len(entries)}_{timestamp}.json"
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=4)

    print(f"Saved {len(entries)} entries to {filename}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("\nERROR:")
        print(e)
    finally:
        input("\nPress Enter to exit...")