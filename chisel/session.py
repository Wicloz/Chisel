from requests import Session
from subprocess import Popen, DEVNULL
from signal import SIGINT
from time import sleep
from tempfile import TemporaryDirectory
from os.path import join
from urllib.parse import urlsplit
import re
from requests.exceptions import ConnectionError, ReadTimeout
from chrome_cookiejar import ChromeCookieJar
import magic
from chisel.database import ChiselDB, TokenLock, cookie_domain


class ChiselSession(Session):
    DB = ChiselDB(True)

    def request(self, method, url, **kwargs):
        assert urlsplit(url).scheme in {'http', 'https'}

        resp = None
        retries = 0
        cookies = kwargs.pop('cookies', {})
        headers = kwargs.pop('headers', {})
        blocked = self.DB.load_history(url)
        proxy = None
        tokens = {}, {}

        while retries < 5:
            if retries != 0:
                sleep(2 ** (retries - 1))

            if retries == 0 or tokens == self.DB.load_tokens(url, proxy):
                proxy = self.DB.get_random_proxy(blocked)
            tokens = self.DB.load_tokens(url, proxy)

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
                    self.DB.update_proxy_status(proxy, False)
                else:
                    retries += 1
                print(f'Retrying "{url}" after connection error ...')
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
                self.DB.save_history(url, blocked)

            if resp.ok or resp.status_code == 404:
                return resp

            if resp.status_code == 401 and urlsplit(url).hostname == '9anime.to':
                challenge = re.findall(r"'(?:\\'|[^'])*'", resp.text)[-1][1:-1]
                solution = ''.join(chr(int(c, 16)) for c in re.findall(r'..', challenge))
                self.DB.save_tokens(url, proxy, solution)

            if resp.headers['content-type'].startswith('text/html') and re.search(r'_cf_chl_', resp.text):
                with TokenLock(self.DB, url, proxy) as lock:
                    if lock.acquired:
                        with TemporaryDirectory() as tmp:

                            flags = ['chromium', '--disable-gpu']
                            if proxy:
                                flags.append('--proxy-server=' + proxy)
                            flags.append('--user-data-dir=' + tmp)
                            flags.append(url)

                            print('> STARTING:', *flags)
                            with Popen(stdout=DEVNULL, stderr=DEVNULL, args=flags) as browser:
                                sleep(9)
                                browser.send_signal(SIGINT)
                                browser.wait()
                            print('> STOPPED:', *flags)

                            for cookie in ChromeCookieJar(join(tmp, 'Default', 'Cookies')):
                                if cookie.domain == cookie_domain(url) and cookie.name == 'cf_clearance':
                                    self.DB.save_tokens(url, proxy, cookie.value)
                                    break

            print(f'Retrying "{url}" after status code {resp.status_code} ...')
            retries += 1

        return resp
