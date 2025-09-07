import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check(ip, session=None):
    key = os.getenv("SHODAN_KEY")
    if not key:
        return {"error": "No Shodan API key"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
    s = session or requests
    r = s.get(url, timeout=10)
    data = r.json()
    return {
        "country": data.get("country_name", ""),
        "org": data.get("org", ""),
        "os": data.get("os", ""),
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "vulns": data.get("vulns", [])
    }
