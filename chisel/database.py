from credentials import mongodb
from pymongo import MongoClient, DESCENDING
from time import sleep
from bs4 import BeautifulSoup
import json
from subprocess import run
from urllib.parse import urlsplit
from random import random
from datetime import datetime
from tldextract import extract
import requests


def cookie_domain(url):
    extracted = extract(url)
    return '.' + extracted.domain + '.' + extracted.suffix


class TokenLock:
    def __init__(self, db, url, proxy):
        self.domain = cookie_domain(url)
        self.ip = db.current_ip_using(proxy)
        self.table = db.database['tokens']
        self.acquired = False

    @property
    def locked(self):
        record = self.table.find_one({
            'domain': self.domain,
            'ip': self.ip,
        })
        return record and 'locked' in record and record['locked']

    def __enter__(self):
        result = self.table.update_one({
            'domain': self.domain,
            'ip': self.ip,
        }, {'$set': {
            'domain': self.domain,
            'ip': self.ip,
            'locked': True,
        }}, upsert=True)

        if result.modified_count or result.upserted_id:
            self.acquired = True

        if not self.acquired:
            while self.locked:
                sleep(1)

        return self

    def __exit__(self, *args):
        if self.acquired:
            self.table.update_one({
                'domain': self.domain,
                'ip': self.ip,
            }, {'$set': {
                'domain': self.domain,
                'ip': self.ip,
                'locked': False,
            }}, upsert=True)


class ChiselDB:
    def __init__(self):
        self.database = MongoClient(**mongodb)['chisel']
        self.database['tokens'].create_index(keys=(('domain', 1), ('ip', 1)), unique=True)
        self.database['tokens'].update_many({}, {'$set': {'locked': False}})
        self.database['history'].create_index(keys='domain', unique=True)
        self.database['proxies'].create_index(keys='proxy', unique=True)
        self.database['proxies'].create_index(keys='works')
        self.database['proxies'].create_index(keys='inserted')

    @staticmethod
    def current_ip_using(proxy):
        if proxy:
            return urlsplit(proxy).hostname
        else:
            return requests.get('https://api64.ipify.org/').text

    def save_tokens(self, url, proxy, token):
        domain = cookie_domain(url)
        ip = self.current_ip_using(proxy)

        soup = BeautifulSoup(run(capture_output=True, universal_newlines=True, args=(
            'chromium', '--disable-gpu', '--headless', '--dump-dom', 'https://chisel.wicloz.rocks/headers',
        )).stdout, 'lxml')
        ua = json.loads(soup.find('pre').text)['user-agent'].replace('HeadlessChrome', 'Chrome')

        self.database['tokens'].update_one({
            'domain': domain,
            'ip': ip,
        }, {'$set': {
            'domain': domain,
            'ip': ip,
            'token': token,
            'ua': ua,
        }}, upsert=True)

    def load_tokens(self, url, proxy):
        document = self.database['tokens'].find_one({
            'domain': cookie_domain(url),
            'ip': self.current_ip_using(proxy),
        })
        if not document or 'token' not in document or 'ua' not in document:
            return {}, {}
        return (
            {key: document['token'] for key in ('cf_clearance', 'waf_cv')},
            {'user-agent': document['ua']},
        )

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
        self.database['history'].update_one({'domain': domain}, {'$inc': increments})

    def load_history(self, url):
        document = self.database['history'].find_one({'domain': urlsplit(url).netloc})
        return document and random() < document['bans'] / (document['visits'] + 1)

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

    def update_proxy_status(self, proxy, works):
        self.database['proxies'].update_one({'proxy': proxy}, {'$set': {'works': works}})

    def get_proxies_by_insertion(self):
        return self.database['proxies'].find().sort('inserted', DESCENDING)
