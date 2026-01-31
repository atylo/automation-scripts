#!/usr/bin/env python3

""""Purchase" all the free titles from Project Egg without having to manually
add them all to your cart.

Written July 27th, 2020 by Obskyr (https://twitter.com/obskyr)!
"""

import sys
import requests
from functools import lru_cache
from getpass import getpass
from urllib.parse import parse_qs, urljoin, urlparse
from bs4 import BeautifulSoup

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0'

LOGIN_URL = 'https://www.amusement-center.com/ja/project/ACEGGMEMCGI/ACEGGMEMLOGIN'
FREE_LIST_URL = 'https://www.amusement-center.com/project/egg/muryolist/'
ADD_TO_CART_URL = 'https://www.amusement-center.com/project/egg/index.cgi?mode=addCart&contcode={contcode}&cartinid={product_id}'
CHECKOUT_URL = 'https://www.amusement-center.com/member/buy-member-detail.cgi?cc=1&id=10'

# Some entries in the "free" list point to old, invalid URLs.
GAME_URL_CORRECTIONS = {
    # DISC SAGA 依頼者はモンスター？ (PC-9801)
    'https://www.amusement-center.com/project/egg/cgi/ecatalog-detail.cgi?contcode=7&product_id=851': 'https://www.amusement-center.com/project/egg/cgi/ecatalog-detail.cgi?contcode=7&product_id=1490',
    # 魔王ゴルベリアス (MSX)
    'https://www.amusement-center.com/project/egg/cgi/ecatalog-detail.cgi?contcode=7&product_id=293': 'https://www.amusement-center.com/project/egg/cgi/ecatalog-detail.cgi?contcode=7&product_id=1382',
    # トップルジップ (PC-8801)
    'https://www.amusement-center.com/project/egg/cgi/ecatalog-detail.cgi?contcode=7&product_id=199': 'https://www.amusement-center.com/project/egg/cgi/ecatalog-detail.cgi?contcode=7&product_id=1494'
}

# Project Egg specifies <meta charset="utf-8"> but sometimes uses EUC-JP...
# to a degree. Pages contain characters that are invalid in EUC-JP as well.
def get_soup(*args, session=None, from_encoding='euc-jp', **kwargs):
    if session is None:
        session = requests.Session()
    return BeautifulSoup(session.get(*args, **kwargs).content.decode(from_encoding, 'replace'), 'html.parser')

class AlreadyPurchasedError(ValueError):
    pass

class AlreadyInCartError(ValueError):
    pass

class NotFreeError(ValueError):
    pass

class NotAvailableError(ValueError):
    pass

class LoginError(ValueError):
    pass

class Buyer:
    def __init__(self):
        self._session = requests.Session()
        self._session.headers['User-Agent'] = USER_AGENT

    def log_in(self, username, password):
        r = self._session.post(LOGIN_URL, data={
            'destination': '/project/egg/memberpage/',
            'credential_0': username,
            'credential_1': password
        })
        if r.status_code != 200:
            raise LoginError("Could not log in with those credentials.")

    def populate_games(self):
        self._games = []
        soup = get_soup(FREE_LIST_URL, session=self._session, from_encoding='utf-8')
        
        first_game_element = soup.find(class_='freegames')
        first_game_url = urljoin(FREE_LIST_URL, first_game_element.find('a')['href'])
        first_game_url = GAME_URL_CORRECTIONS.get(first_game_url, first_game_url)
        first_game_list_title = first_game_element.find('h4').get_text(strip=True)
        first_game_list_title = first_game_list_title[:first_game_list_title.index('（')]
        self._games.append(Game(self._session, first_game_url, first_game_list_title))

        list_element = soup.find(class_='freebox')
        for item in list_element(recursive=False):
            cur_url = urljoin(FREE_LIST_URL, item.find('a')['href'])
            cur_url = GAME_URL_CORRECTIONS.get(cur_url, cur_url)
            cur_list_title = str(item.find('span').contents[-1])
            self._games.append(Game(self._session, cur_url, cur_list_title))
    
    def check_out(self):
        assert self._session.get(CHECKOUT_URL).status_code == 200

    def execute(self, username, password):
        print("Logging in...")
        self.log_in(username, password)
        print("Getting list of games...")
        self.populate_games()
        for game in self._games:
            try:
                game.add_to_cart()
            except AlreadyPurchasedError:
                print(f"Already purchased: {game.title}", file=sys.stderr)
            except AlreadyInCartError:
                print(f"Already in cart:   {game.title}", file=sys.stderr)
            except NotFreeError:
                print(f"Not free:          {game.title}", file=sys.stderr)
            except NotAvailableError:
                print(f"Not available:     {game.list_title} ({game.url})", file=sys.stderr)
            else:
                print(f"Added to cart:     {game.title}")
        print("Checking out...")
        self.check_out()

class Game:
    def __init__(self, session, url, list_title):
        self._session = session
        self.url = url
        self.list_title = list_title
    
    @property
    @lru_cache(maxsize=1)
    def _soup(self):
        r = self._session.get(self.url, allow_redirects=False)
        if r.status_code == 302:
            raise NotAvailableError("Game not available.")
        assert r.status_code == 200
        return BeautifulSoup(r.content.decode('euc-jp', 'replace'), 'html.parser')

    @property
    @lru_cache(maxsize=1)
    def title(self):
        return self._soup.find(class_='game_title').get_text(strip=True)

    def add_to_cart(self):
        status = self._soup.find(class_='gamestatus')
        if 'bought' in status['class']:
            raise AlreadyPurchasedError("Game already purchased.")
        elif status.get_text(strip=True) == "レジへ":
            raise AlreadyInCartError("Game already in cart.")
        elif status.get_text(strip=True) != "無料":
            raise NotFreeError("Game isn't free.")
        assert 'buynow' in status['class'] # Sanity check; why not!
        query = parse_qs(urlparse(self.url).query)
        assert self._session.get(ADD_TO_CART_URL.format(contcode=query['contcode'][0], product_id=query['product_id'][0]), allow_redirects=False).status_code == 302

def main(*argv):
    print("Please enter your Project Egg...")
    username = input("Username: ")
    password = getpass("Password: ")
    buyer = Buyer()
    try:
        buyer.execute(username, password)
    except LoginError:
        print("Could not log in with those credentials.", file=sys.stderr)
        return 1
    print(f"Successfully purchased all free games for the account \"{username}\"!")
    return 0

if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
