#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import cloudscraper
import validators as valid
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError

requests = cloudscraper.create_scraper()


class Chisel(BaseHTTPRequestHandler):
    def do_GET(self):
        prefix = ''
        if self.path.startswith('/browser/'):
            prefix = '/browser/'

        split = self.path.split('/', 2)
        if len(split) != 3 or not valid.url(split[2]):
            self.send_error(400)
            return

        try:
            resp = requests.get(split[2])
        except ConnectionError:
            self.send_error(502)
            return

        self.send_response(resp.status_code)
        if 'content-type' in resp.headers:
            self.send_header('content-type', resp.headers['content-type'])
        self.end_headers()

        if 'text/html' in resp.headers['content-type']:
            soup = BeautifulSoup(resp.content, 'lxml')
            for tag in soup(href=True):
                tag['href'] = prefix + urljoin(split[2], tag['href'])
            for tag in soup(src=True):
                tag['src'] = prefix + urljoin(split[2], tag['src'])
            self.wfile.write(soup.encode())

        else:
            self.wfile.write(resp.content)


if __name__ == '__main__':
    HTTPServer(('', 1234), Chisel).serve_forever()
