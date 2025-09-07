import requests

def make_session(proxy_url=None):
    s = requests.Session()
    if proxy_url:
        s.proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
    return s
