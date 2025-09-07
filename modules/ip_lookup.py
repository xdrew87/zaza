import requests
import socket
import re

def is_valid_ip(ip):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) is not None

def is_valid_domain(domain):
    return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$", domain) is not None

def lookup(ip, session=None):
    url = f"https://ip-api.com/json/{ip}?fields=66846719"
    s = session or requests
    r = s.get(url, timeout=10)
    data = r.json()
    return {
        "asn": data.get("as", ""),
        "isp": data.get("isp", ""),
        "org": data.get("org", ""),
        "country": data.get("country", ""),
        "region": data.get("regionName", ""),
        "city": data.get("city", ""),
        "lat": data.get("lat", ""),
        "lon": data.get("lon", ""),
        "reverse": data.get("reverse", ""),
        "query": data.get("query", "")
    }

def reverse_dns(ip, session=None):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def domain_lookup(domain, session=None):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None
