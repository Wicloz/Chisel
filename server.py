#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import cloudscraper

requests = cloudscraper.create_scraper()


class CloudProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        resp = requests.get(self.path[1:])
        self.send_response(resp.status_code)
        self.end_headers()
        self.wfile.write(resp.content)


if __name__ == '__main__':
    HTTPServer(('', 1234), CloudProxy).serve_forever()
