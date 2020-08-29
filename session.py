from requests import Session
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.expected_conditions import title_is
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from random import choice
from time import sleep
from cloudscraper import CloudScraper
from http.cookiejar import CookiePolicy
from pymongo import MongoClient, DESCENDING
from tldextract import extract
from credentials import mongodb
from tempfile import TemporaryDirectory
from filelock import FileLock
from os.path import join
from urllib.parse import urlsplit
import re
from random import random
from requests.exceptions import ConnectionError, ReadTimeout
import pandas as pd
import requests
from datetime import datetime


class BlockCookies(CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False


class ChiselSession(Session):
    def __init__(self):
        super().__init__()
        self.cookies.set_policy(BlockCookies())
        self.options = Options()
        self.options.headless = True
        self.options.add_argument('window-size=1920,1080')
        with Chrome(options=self.options) as browser:
            user_agent = browser.execute_script('return navigator.userAgent').replace('Headless', '')
            self.headers.update({'user-agent': user_agent})
            self.options.add_argument('user-agent=' + user_agent)
        self.database = MongoClient(**mongodb)['chisel']
        self.database['tokens'].create_index(keys='domain', unique=True)
        self.database['history'].create_index(keys='domain', unique=True)
        self.database['proxies'].create_index(keys='proxy', unique=True)
        self.database['proxies'].create_index(keys='works')
        self.database['proxies'].create_index(keys='inserted')
        self.locks = TemporaryDirectory()

    @staticmethod
    def domain(url):
        extracted = extract(url)
        return '.' + extracted.domain + '.' + extracted.suffix

    def save_tokens(self, url, cookie1, cookie2):
        if not cookie1 or not cookie2:
            return
        self.database['tokens'].update({'domain': self.domain(url)}, {
            'domain': self.domain(url),
            'token1': cookie1['value'],
            'token2': cookie2['value'],
        }, True)

    def load_tokens(self, url):
        document = self.database['tokens'].find_one({'domain': self.domain(url)})
        if document is None:
            return {}
        return {'__cfduid': document['token1'], 'cf_clearance': document['token2']}

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
        resp = None
        retries = 0
        cookies = kwargs.pop('cookies', {})
        blocked = self.load_history(url)

        while retries < 5:
            pass

            proxy = self.get_random_proxy(blocked)
            tokens = self.load_tokens(url)
            try:
                resp = super().request(
                    method=method,
                    url=url,
                    cookies={**cookies, **tokens},
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
            if re.search(r'<title>\s*BANNED\s*</title>', resp.text):
                resp.status_code = 403

            if not blocked:
                blocked = resp.status_code in (429, 403)
                self.save_history(url, blocked)

            if resp.ok or resp.status_code == 404:
                return resp

            if CloudScraper.is_IUAM_Challenge(resp) or CloudScraper.is_New_IUAM_Challenge(resp):
                with FileLock(join(self.locks.name, self.domain(url))):
                    if tokens == self.load_tokens(url):
                        with Chrome(options=self.options) as browser:
                            with open('selenium.js', 'r') as fp:
                                browser.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': fp.read()})
                            browser.get(url)
                            actions = ActionChains(browser)
                            for _ in range(30):
                                actions.send_keys(choice((Keys.DOWN, Keys.UP, Keys.LEFT, Keys.RIGHT))).perform()
                            try:
                                WebDriverWait(browser, 30).until_not(title_is('Just a moment...'))
                            except TimeoutException:
                                pass
                            self.save_tokens(url, browser.get_cookie('__cfduid'), browser.get_cookie('cf_clearance'))

            print('Retrying "{}" after status code {} ...'.format(url, resp.status_code))
            retries += 1
            sleep(1)

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
