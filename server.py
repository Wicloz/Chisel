#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import cloudscraper
import validators as valid
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError
from requests.structures import CaseInsensitiveDict

request = cloudscraper.create_scraper().request


class Chisel(BaseHTTPRequestHandler):
    def __getattribute__(self, item):
        if item.startswith('do_'):
            return self.proxy
        else:
            return super().__getattribute__(item)

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
        headers['referer'] = split[2]

        # send upstream request
        try:
            resp = request(
                method=self.command,
                url=split[2],
                data=content,
                headers=headers,
            )
        except ConnectionError:
            self.send_error(502)
            return

        self.send_response(resp.status_code)
        if 'content-type' in resp.headers:
            self.send_header('content-type', resp.headers['content-type'])
        self.end_headers()

        if self.command == 'HEAD':
            return

        if split[1] == 'browser' and 'content-type' in resp.headers and 'text/html' in resp.headers['content-type']:
            soup = BeautifulSoup(resp.content, 'lxml')
            for tag in soup(href=True):
                tag['href'] = '/browser/' + urljoin(split[2], tag['href'])
            for tag in soup(src=True):
                tag['src'] = '/browser/' + urljoin(split[2], tag['src'])
            self.wfile.write(soup.encode())

        else:
            self.wfile.write(resp.content)


if __name__ == '__main__':
    ThreadingHTTPServer(('', 1234), Chisel).serve_forever()
