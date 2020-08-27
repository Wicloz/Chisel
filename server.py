#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import validators as valid
from urllib.parse import urljoin, urlsplit, urlunsplit
from bs4 import BeautifulSoup
from requests.structures import CaseInsensitiveDict
from http.cookies import SimpleCookie
from session import ChiselSession
import re
import magic


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

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except ConnectionAbortedError:
            pass
        self.rfile = self.connection.makefile('rb', self.rbufsize)

    def proxy(self):
        # process request urls
        c_mode, c_target = self.process_url(self.path)
        p_mode, p_target = self.process_url(self.headers['referer'])
        parsed = urlsplit(c_target)

        # handle invalid requests
        if c_mode is None or c_target is None:
            if p_mode is None or p_target is None:
                self.send_error(400)
            else:
                self.send_response(307)
                self.send_header('location', '/' + p_mode + '/' + urljoin(p_target, self.path))
                self.send_header('vary', 'referer')
                self.send_header('content-length', '0')
                self.end_headers()
            return

        # process request body
        content = None
        if 'content-length' in self.headers:
            content = self.rfile.read(int(self.headers['content-length']))

        # process request headers
        headers = CaseInsensitiveDict(self.headers)
        headers.pop('user-agent', None)
        headers.pop('accept-encoding', None)
        headers.pop('te', None)
        headers.pop('connection', None)
        headers.pop('host', None)
        headers['origin'] = parsed.scheme + '://' + parsed.netloc
        headers['referer'] = p_target

        # process request cookies
        cookies = {key: value.value for key, value in SimpleCookie(headers.pop('cookie', None)).items()}
        cookies.pop('__cfduid', None)
        cookies.pop('cf_clearance', None)

        # send upstream request
        resp = session.request(
            method=self.command,
            url=c_target,
            data=content,
            headers=headers,
            cookies=cookies,
            allow_redirects=c_mode != 'browser',
        )
        if resp is None:
            self.send_error(502)
            return

        # send initial response
        self.send_response(resp.status_code)
        for keep in ('set-cookie', 'vary'):
            if keep in resp.headers:
                self.send_header(keep, resp.headers[keep])
        if 'location' in resp.headers:
            self.send_header('location', '/' + c_mode + '/' + urljoin(c_target, resp.headers['location']))

        # end for HEAD requests
        if self.command == 'HEAD':
            self.end_headers()
            return

        # process response body
        if c_mode == 'browser' and 'content-type' in resp.headers:
            pass

            if 'text/html' in resp.headers['content-type'] or 'application/xhtml+xml' in resp.headers['content-type']:
                soup = BeautifulSoup(resp.content, 'lxml')
                base = soup.find('base')
                base = base['href'] if base else c_target
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

    @staticmethod
    def process_url(url):
        if not url:
            return None, None
        split = urlunsplit(('', '') + urlsplit(url)[2:]).split('/', 2)
        if len(split) != 3 or not valid.url(split[2], True):
            return None, None
        return split[1], split[2]

    @staticmethod
    def expand_urls_in_text(text, scheme):
        return re.sub(r'([\"\'])(.*?)(?:https?:)?//(.*?[^\\])?\1', '\\1\\2/browser/' + scheme + '://\\3\\1', text)


if __name__ == '__main__':
    # set up the shared session
    session = ChiselSession()
    # start the HTTP server
    print('Starting HTTP server on port 1234 ...')
    ThreadingHTTPServer(('', 1234), ChiselProxy).serve_forever()
