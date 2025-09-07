import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check(target, session=None):
    key = os.getenv("VT_KEY")
    if not key:
        return {"error": "No VirusTotal API key"}
    s = session or requests
    if "." in target and not target.replace(".", "").isdigit():
        # domain
        url = f"https://www.virustotal.com/api/v3/domains/{target}"
    else:
        # IP
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    headers = {"x-apikey": key}
    r = s.get(url, headers=headers, timeout=10)
    data = r.json().get("data", {}).get("attributes", {})
    return {
        "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
        "suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
        "harmless": data.get("last_analysis_stats", {}).get("harmless", 0),
        "reputation": data.get("reputation", 0),
        "tags": data.get("tags", [])
    }
