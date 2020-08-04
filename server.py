#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from requests import Session
import validators as valid
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError
from requests.structures import CaseInsensitiveDict
from http.cookies import SimpleCookie
from time import sleep
from cloudscraper import CloudScraper
from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.expected_conditions import title_is
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
from random import choice


def download(**kwargs):
    for _ in range(3):
        resp = session.request(**kwargs)

        if resp.status_code in (200, 404):
            return resp

        if CloudScraper.is_IUAM_Challenge(resp) or CloudScraper.is_New_IUAM_Challenge(resp):
            with Chrome(options=options) as browser:
                with open('selenium.js', 'r') as fp:
                    browser.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': fp.read()})
                browser.get(resp.url)
                actions = ActionChains(browser)
                for _ in range(30):
                    actions.send_keys(choice((Keys.DOWN, Keys.UP, Keys.LEFT, Keys.RIGHT))).perform()
                try:
                    WebDriverWait(browser, 30).until_not(title_is('Just a moment...'))
                except TimeoutException:
                    pass
                for cookie in browser.get_cookies():
                    session.cookies.set(name=cookie['name'], value=cookie['value'], domain=cookie['domain'])

        print('Retrying "{}" with status code {} ...'.format(resp.url, resp.status_code))
        sleep(1)

    return resp


class Chisel(BaseHTTPRequestHandler):
    def __getattribute__(self, item):
        if item.startswith('do_'):
            return self.proxy
        elif item.startswith('log_'):
            return self.disabled
        else:
            return super().__getattribute__(item)

    @staticmethod
    def disabled(*args, **kwargs):
        pass

    def proxy(self):
        # process request url
        split = self.path.split('/', 2)
        if len(split) != 3 or not valid.url(split[2]):
            if 'referer' in self.headers and '/browser/' in self.headers['referer']:
                split = ['', 'browser', urljoin(self.headers['referer'].split('/browser/', 1)[1], self.path)]
        if len(split) != 3 or not valid.url(split[2]):
            self.send_error(400)
            return
        parsed = urlparse(split[2])

        # process request body
        content = None
        if 'content-length' in self.headers:
            content = self.rfile.read(int(self.headers['content-length']))

        # process request headers
        headers = CaseInsensitiveDict(self.headers)
        headers['host'] = parsed.netloc
        headers['origin'] = parsed.scheme + '://' + parsed.netloc
        headers.pop('referer', None)
        headers.pop('user-agent', None)

        # process request cookies
        cookies = {key: value.value for key, value in SimpleCookie(headers.pop('cookie', None)).items()}
        cookies.pop('__cfduid', None)
        cookies.pop('cf_clearance', None)

        # send upstream request
        try:
            resp = download(
                method=self.command,
                url=split[2],
                data=content,
                headers=headers,
                cookies=cookies,
            )
        except ConnectionError:
            self.send_error(502)
            return

        # send initial response
        self.send_response(resp.status_code)
        for keep in ('content-type', 'set-cookie'):
            if keep in resp.headers:
                self.send_header(keep, resp.headers[keep])

        # end for HEAD requests
        if self.command == 'HEAD':
            self.end_headers()
            return

        # process HTML for 'browser' requests
        if split[1] == 'browser' and 'content-type' in resp.headers and 'text/html' in resp.headers['content-type']:
            soup = BeautifulSoup(resp.content, 'lxml')
            for tag in soup(href=True):
                tag['href'] = '/browser/' + urljoin(split[2], tag['href'])
            for tag in soup(src=True):
                tag['src'] = '/browser/' + urljoin(split[2], tag['src'])
            with open('intercept.js', 'r') as fp:
                tag = soup.new_tag('script')
                tag.append(fp.read())
                soup.insert(0, tag)

            # finalize response body
            body = soup.encode()
        else:
            body = resp.content

        # send body responses
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    # set up the shared Session
    session = Session()
    options = Options()
    options.headless = True
    options.add_argument('window-size=1920,1080')
    with Chrome(options=options) as browser:
        user_agent = browser.execute_script('return navigator.userAgent').replace('Headless', '')
        session.headers = {'user-agent': user_agent}
        options.add_argument('user-agent=' + user_agent)

    # cleanup local variables
    del browser
    del user_agent

    # start the HTTP server
    print('Starting HTTP server on port 1234 ...')
    ThreadingHTTPServer(('', 1234), Chisel).serve_forever()
