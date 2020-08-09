#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import validators as valid
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError
from requests.structures import CaseInsensitiveDict
from http.cookies import SimpleCookie
from session import ChiselSession


class ChiselProxy(BaseHTTPRequestHandler):
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
        headers.pop('accept-encoding', None)
        headers.pop('te', None)

        # process request cookies
        cookies = {key: value.value for key, value in SimpleCookie(headers.pop('cookie', None)).items()}
        cookies.pop('__cfduid', None)
        cookies.pop('cf_clearance', None)

        # send upstream request
        try:
            resp = session.request(
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
        for keep in ('content-type', 'set-cookie', 'vary'):
            if keep in resp.headers:
                self.send_header(keep, resp.headers[keep])

        # end for HEAD requests
        if self.command == 'HEAD':
            self.end_headers()
            return

        # process HTML for 'browser' requests
        if split[1] == 'browser' and 'content-type' in resp.headers and (
                'text/html' in resp.headers['content-type'] or 'application/xhtml+xml' in resp.headers['content-type']
        ):
            soup = BeautifulSoup(resp.content, 'lxml')
            base = soup.find('base')
            base = base['href'] if base else split[2]
            for tag in soup(href=True):
                tag['href'] = '/browser/' + urljoin(base, tag['href'])
            for tag in soup(src=True):
                tag['src'] = '/browser/' + urljoin(base, tag['src'])
            with open('intercept.js', 'r') as fp:
                tag = soup.new_tag('script')
                tag.append(fp.read())
                soup.insert(0, tag)
            body = soup.encode()

        # proxy other requests
        else:
            body = resp.content

        # send body responses
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    # set up the shared session
    session = ChiselSession()
    # start the HTTP server
    print('Starting HTTP server on port 1234 ...')
    ThreadingHTTPServer(('', 1234), ChiselProxy).serve_forever()
