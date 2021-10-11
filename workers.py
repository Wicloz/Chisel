#!/usr/bin/env python3

from chisel.database import ChiselDB
import pandas as pd
import requests
from requests.exceptions import ConnectionError, ReadTimeout

if __name__ == '__main__':
    cdb = ChiselDB()
    while True:
        pass

        df = pd.read_html(requests.get('https://www.socks-proxy.net/').text)[0][:-1]
        df['Port'] = df['Port'].astype(int).astype(str)
        df['Version'] = df['Version'].str.lower()
        cdb.store_proxy_series(df['Version'] + '://' + df['IP Address'] + ':' + df['Port'])

        df = pd.read_html(requests.get('https://free-proxy-list.net/').text)[0][:-1]
        df['Port'] = df['Port'].astype(int).astype(str)
        df['Https'] = df['Https'].map({'yes': 'https', 'no': 'http'})
        cdb.store_proxy_series(df['Https'] + '://' + df['IP Address'] + ':' + df['Port'])

        for proxy in [doc['proxy'] for doc in cdb.get_proxies_by_insertion()]:
            try:
                works = all(requests.head(
                    url=protocol + '://connectivitycheck.gstatic.com/generate_204',
                    proxies={protocol: proxy},
                    timeout=5,
                ).status_code == 204 for protocol in ('http', 'https'))
            except (ConnectionError, ReadTimeout):
                works = False

            print(proxy, works)
            cdb.update_proxy_status(proxy, works)
