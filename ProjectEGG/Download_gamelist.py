import json
import requests
from io import StringIO
from os import SEEK_END
from urllib.parse import unquote_plus

USER_AGENT = 'c384da2W9f73dz20403d'

def get_purchased(username, password):
    r = requests.post(
        'http://api.amusement-center.com/api/dcp/v1/getcontentslist',
        headers={'User-Agent': USER_AGENT},
        data={
            'userid': username,
            'passwd': password
        }
    )
    if not r.status_code == 200:
        raise ConnectionError("Could not get list of purchased content.")

    data = r.content.decode('ascii')
    first_comma_pos = data.find(',')
    if first_comma_pos == -1:
        status = data
        data = ""
    else:
        status = data[:first_comma_pos]
        data = data[first_comma_pos + 1:]
    if status != 'ok':
        raise ValueError("Could not get list of purchased content. Login credentials may have been incorrect.")

    return tuple(parse_content_entries(data))

def parse_content_entries(data):
    data = data.replace(',', '\n')
    data = StringIO(data)
    data.seek(0, SEEK_END)
    end = data.tell()
    data.seek(0)
    while data.tell() < end:
        yield parse_content_entry(data)

CONTENT_PROPERTIES = (
    # (key, transformer).
    ('egg',               str),
    ('version',           str),
    ('title',             str),
    ('productId',         str),
    ('publisher',         str),
    ('platform',          str),
    ('genre',             str),
    ('year',              str),
    ('mystery1',          str), # always 0
    ('gameFilename',      str),
    ('lastUpdated',       str), # Some sort of date...
    ('hasMusic',          lambda s: bool(int(s))), # 0 or 1, encryption or music present...?
    ('owned',             lambda s: bool(int(s))),
    ('thumbnailFilename', str),
    ('description',       str),
    ('mystery5',          str), # used to be always 1, now always 0
    ('manualFilename',    str),
    ('manualDate',        str), # Only appears if the game has a manual...?
    ('musicFilename',     str), # Only appears if the game has music...?
    ('musicDate',         str),
    ('releaseDate',       str), # Available to purchase in the store
    ('storeExpiryDate',   str), # Some future date...? An expiration?
    ('uploadDate',        str), # A date - possibly the "added on" date?
    ('mystery8',          str), # Another future date; possibly always the same as mystery6.
    ('mystery9',          str), # 679 or 1194, pbly referencing a tool or original game. 
    ('region',            int), # 0: Japanese; 1: English
    ('currentPrice',      str)
)

def parse_content_entry(data):
    return  {key: transformer(unquote_plus(data.readline().rstrip('\n'), encoding='euc-jp'))
                for key, transformer in CONTENT_PROPERTIES}

print("Downloading please wait...")
username = 'lolcat54'
password = 'lostmypass'

entries = get_purchased(username, password)
with open("data.json", "w", encoding="utf-8") as f:
    json.dump(entries, f, ensure_ascii=False, indent=4)
