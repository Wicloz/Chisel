from requests import Session
from subprocess import Popen, DEVNULL, run
from signal import SIGINT
from time import sleep
from cloudscraper import CloudScraper
from http.cookiejar import CookiePolicy
from pymongo import MongoClient, DESCENDING
from tldextract import extract
from credentials import mongodb
from tempfile import TemporaryDirectory
from os.path import join
from urllib.parse import urlsplit
import re
from random import random
from requests.exceptions import ConnectionError, ReadTimeout
import pandas as pd
import requests
from datetime import datetime
from chrome_cookiejar import ChromeCookieJar
import magic


class BlockCookies(CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False


class ChiselSession(Session):
    def __init__(self):
        super().__init__()

        self.database = MongoClient(**mongodb)['chisel']
        self.database['tokens'].create_index(keys=(('domain', 1), ('ip', 1)), unique=True)
        self.database['history'].create_index(keys='domain', unique=True)
        self.database['proxies'].create_index(keys='proxy', unique=True)
        self.database['proxies'].create_index(keys='works')
        self.database['proxies'].create_index(keys='inserted')

        # TODO: consolidate and clean up
        self.IPv4 = requests.get('https://api.ipify.org/').text
        self.ua = re.search(r'"rawUa":"(.+?)"', run(capture_output=True, universal_newlines=True, args=(
            'chromium', '--headless', '--disable-gpu', '--dump-dom', 'https://www.whatsmyua.info/api/v1/ua',
        )).stdout).group(1).replace('HeadlessChrome', 'Chrome')

        self.cookies.set_policy(BlockCookies())

    @staticmethod
    def _domain(url):
        extracted = extract(url)
        return '.' + extracted.domain + '.' + extracted.suffix

    def _ip(self, proxy):
        if proxy:
            return urlsplit(proxy).hostname
        else:
            return self.IPv4

    def save_tokens(self, url, proxy, token, ua):
        domain = self._domain(url)
        ip = self._ip(proxy)

        self.database['tokens'].update({
            'domain': domain,
            'ip': ip,
        }, {
            'domain': domain,
            'ip': ip,
            'token': token,
            'ua': ua,
        }, True)

    def load_tokens(self, url, proxy):
        document = self.database['tokens'].find_one({'domain': self._domain(url), 'ip': self._ip(proxy)})
        if document is None:
            return {}, {}
        return {'cf_clearance': document['token']}, {'user-agent': document['ua']}

    def save_history(self, url, blocked):
        domain = urlsplit(url).netloc

        if not self.database['history'].count({'domain': domain}):
            self.database['history'].insert({
                'domain': domain,
                'visits': 0,
                'bans': 0,
            })

        increments = {'visits': 1}
        if blocked:
            increments['bans'] = 1
        self.database['history'].update({'domain': domain}, {'$inc': increments})

    def load_history(self, url):
        document = self.database['history'].find_one({'domain': urlsplit(url).netloc})
        return document and random() < document['bans'] / (document['visits'] + 1)

    def request(self, method, url, **kwargs):
        assert urlsplit(url).scheme in {'http', 'https'}

        resp = None
        retries = 0
        cookies = kwargs.pop('cookies', {})
        headers = kwargs.pop('headers', {})
        blocked = self.load_history(url)
        proxy = None
        tokens = {}, {}

        while retries < 5:
            if retries != 0:
                sleep(2 ** (retries - 1))

            if retries == 0 or tokens == self.load_tokens(url, proxy):
                proxy = self.get_random_proxy(blocked)
            tokens = self.load_tokens(url, proxy)

            try:
                resp = super().request(
                    method=method,
                    url=url,
                    cookies={**cookies, **tokens[0]},
                    headers={**headers, **tokens[1]},
                    proxies={'http': proxy, 'https': proxy},
                    timeout=60,
                    **kwargs,
                )
            except (ConnectionError, ReadTimeout):
                if proxy:
                    self.database['proxies'].update({'proxy': proxy}, {'$set': {'works': False}})
                else:
                    retries += 1
                print('Retrying "{}" after connection error ...'.format(url))
                continue

            if 'content-type' not in resp.headers:
                resp.headers['content-type'] = magic.from_buffer(resp.content, True)
            if 'content-length' not in resp.headers:
                resp.headers['content-length'] = str(len(resp.content))

            if resp.headers['content-type'].startswith('text/html') \
                    and re.search(r'<title>\s*BANNED\s*</title>', resp.text):
                resp.status_code = 403

            if not blocked:
                blocked = resp.status_code in {429, 403}
                self.save_history(url, blocked)

            if resp.ok or resp.status_code == 404:
                return resp

            # TODO: custom check and remove module
            # TODO: prevent multiple browsers for same challenge
            if CloudScraper.is_IUAM_Challenge(resp) or CloudScraper.is_New_IUAM_Challenge(resp):
                with TemporaryDirectory() as tmp:
                    # TODO: use flags to set proxy
                    browser = Popen(stdout=DEVNULL, stderr=DEVNULL, args=(
                        'chromium', '--disable-gpu', '--user-data-dir=' + tmp, url,
                    ))
                    sleep(10)
                    browser.send_signal(SIGINT)
                    browser.wait()
                    for cookie in ChromeCookieJar(join(tmp, 'Default', 'Cookies')):
                        if cookie.domain == self._domain(url) and cookie.name == 'cf_clearance':
                            self.save_tokens(url, proxy, cookie.value, self.ua)
                            break

            print('Retrying "{}" after status code {} ...'.format(url, resp.status_code))
            retries += 1

        return resp

    def get_random_proxy(self, enabled):
        if not enabled:
            return None
        return self.database['proxies'].aggregate([
            {'$match': {'works': True}},
            {'$sample': {'size': 1}},
        ]).next()['proxy']

    def store_proxy_series(self, series):
        for item in series:
            if not self.database['proxies'].count({'proxy': item}):
                self.database['proxies'].insert({
                    'proxy': item,
                    'works': True,
                    'inserted': datetime.now(),
                })

    def worker(self):
        while True:
            pass

            df = pd.read_html(requests.get('https://www.socks-proxy.net/').text)[0][:-1]
            df['Port'] = df['Port'].astype(int).astype(str)
            df['Version'] = df['Version'].str.lower()
            self.store_proxy_series(df['Version'] + '://' + df['IP Address'] + ':' + df['Port'])

            df = pd.read_html(requests.get('https://free-proxy-list.net/').text)[0][:-1]
            df['Port'] = df['Port'].astype(int).astype(str)
            df['Https'] = df['Https'].map({'yes': 'https', 'no': 'http'})
            self.store_proxy_series(df['Https'] + '://' + df['IP Address'] + ':' + df['Port'])

            for proxy in [doc['proxy'] for doc in self.database['proxies'].find().sort('inserted', DESCENDING)]:
                try:
                    works = all(requests.head(
                        url=protocol + '://connectivitycheck.gstatic.com/generate_204',
                        proxies={protocol: proxy},
                        timeout=5,
                    ).status_code == 204 for protocol in ('http', 'https'))
                except (ConnectionError, ReadTimeout):
                    works = False
                self.database['proxies'].update({'proxy': proxy}, {'$set': {'works': works}})
