import whois
from datetime import datetime

def check_domain_age(url):
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            ok = age_days > 180
            msg = (f"Domain is {age_days} days old" if ok else
                   f"Very new domain ({age_days} days) — suspicious")
            return {"name": "Domain Age", "ok": ok, "msg": msg}
    except Exception:
        pass
    return {"name": "Domain Age", "ok": False,
            "msg": "Could not retrieve WHOIS data"}