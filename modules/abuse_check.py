import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check(ip, session=None):
    key = os.getenv("ABUSEIPDB_KEY")
    if not key:
        return {"error": "No AbuseIPDB API key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    s = session or requests
    r = s.get(url, headers=headers, params=params, timeout=10)
    data = r.json().get("data", {})
    return {
        "score": data.get("abuseConfidenceScore", 0),
        "country": data.get("countryCode", ""),
        "usage": data.get("usageType", ""),
        "domain": data.get("domain", ""),
        "totalReports": data.get("totalReports", 0),
        "lastReported": data.get("lastReportedAt", "")
    }
