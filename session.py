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
from pymongo import MongoClient
from tldextract import extract
from credentials import mongodb
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
            'solved': datetime.utcnow(),
        }, True)

    def load_tokens(self, url):
        document = self.database['tokens'].find_one({'domain': self.domain(url)})
        if document is None:
            return {}
        return {'__cfduid': document['token1'], 'cf_clearance': document['token2']}

    def request(self, method, url, **kwargs):
        cookies = kwargs.pop('cookies', {})

        for _ in range(3):
            resp = super().request(method=method, url=url, cookies={**cookies, **self.load_tokens(url)}, **kwargs)

            if resp.status_code in (200, 404):
                return resp

            if CloudScraper.is_IUAM_Challenge(resp) or CloudScraper.is_New_IUAM_Challenge(resp):
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

            print('Retrying "{}" with status code {} ...'.format(url, resp.status_code))
            sleep(1)

        return resp
