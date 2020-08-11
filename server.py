#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import validators as valid
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError
from requests.structures import CaseInsensitiveDict
from http.cookies import SimpleCookie
from session import ChiselSession
import re
import magic


class Referer:
    mode = None
    path = None


class ChiselProxy(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

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
            redirect = urljoin(self.referer.path, self.path)
            if valid.url(redirect):
                self.send_response(307)
                self.send_header('location', self.referer.mode + redirect)
                self.send_header('content-length', '0')
                self.end_headers()
            else:
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
        headers['referer'] = self.referer.path
        headers.pop('user-agent', None)
        headers.pop('accept-encoding', None)
        headers.pop('te', None)
        headers.pop('connection', None)

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
        for keep in ('set-cookie', 'vary'):
            if keep in resp.headers:
                self.send_header(keep, resp.headers[keep])

        # end for HEAD requests
        if self.command == 'HEAD':
            self.end_headers()
            return

        # process response body
        if split[1] == 'browser' and 'content-type' in resp.headers:
            pass

            if 'text/html' in resp.headers['content-type'] or 'application/xhtml+xml' in resp.headers['content-type']:
                soup = BeautifulSoup(resp.content, 'lxml')
                base = soup.find('base')
                base = base['href'] if base else split[2]
                for tag in soup(href=True):
                    tag['href'] = '/browser/' + urljoin(base, tag['href'])
                for tag in soup(src=True):
                    tag['src'] = '/browser/' + urljoin(base, tag['src'])
                for tag in soup('script'):
                    if tag.string:
                        tag.string = self.expand_urls_in_text(tag.string, parsed.scheme)
                with open('intercept.js', 'r') as fp:
                    tag = soup.new_tag('script')
                    tag.append(fp.read())
                    soup.insert(0, tag)
                body = soup.encode()

            elif 'text/' in resp.headers['content-type'] and (resp.encoding or resp.apparent_encoding):
                body = self.expand_urls_in_text(resp.text, parsed.scheme).encode(resp.encoding or resp.apparent_encoding)

            else:
                body = resp.content
        else:
            body = resp.content

        # send response body and related headers
        self.send_header(
            'content-type',
            resp.headers['content-type'] if 'content-type' in resp.headers else magic.from_buffer(body, True),
        )
        self.send_header('content-length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @property
    def referer(self):
        data = Referer()

        if 'referer' in self.headers:
            split = urlparse(self.headers['referer']).path.split('/', 2)
            if len(split) == 3 and valid.url(split[2]):
                data.mode = '/' + split[1] + '/'
                data.path = split[2]

        return data

    @staticmethod
    def expand_urls_in_text(text, scheme):
        return re.sub(r'([\"\'])(.*?)(?:https?:)?//(.*?[^\\])?\1', '\\1\\2/browser/' + scheme + '://\\3\\1', text)


if __name__ == '__main__':
    # set up the shared session
    session = ChiselSession()
    # start the HTTP server
    print('Starting HTTP server on port 1234 ...')
    ThreadingHTTPServer(('', 1234), ChiselProxy).serve_forever()
