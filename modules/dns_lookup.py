import dns.resolver

def get_records(domain):
    records = {}
    for rtype in ["A", "MX", "TXT", "NS"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(a) for a in answers]
        except Exception:
            records[rtype] = []
    return records
