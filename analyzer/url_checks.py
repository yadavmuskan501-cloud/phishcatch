import re, math, requests, socket
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq',
                   '.xyz', '.top', '.work', '.click'}

BRAND_KEYWORDS = ['paypal', 'google', 'amazon', 'microsoft',
                  'apple', 'bank', 'secure', 'login', 'verify']

def check_https(url):
    ok = url.startswith("https://")
    return {"name": "HTTPS", "ok": ok,
            "msg": "Secure HTTPS" if ok else "No HTTPS"}

def check_suspicious_tld(url):
    ext = tldextract.extract(url)
    tld = f".{ext.suffix}"
    bad = any(tld.endswith(t) for t in SUSPICIOUS_TLDS)
    return {"name": "Suspicious TLD", "ok": not bad,
            "msg": "Normal TLD" if not bad else f"Bad TLD: {tld}"}

def check_url_length(url):
    ok = len(url) < 75
    return {"name": "URL Length", "ok": ok,
            "msg": f"Normal ({len(url)} chars)" if ok else
                   f"Too long ({len(url)} chars)"}

def check_entropy(url):
    domain = urlparse(url).netloc or url
    prob = [domain.count(c)/len(domain) for c in set(domain)]
    entropy = -sum(p * math.log2(p) for p in prob if p > 0)
    ok = entropy < 3.5
    return {"name": "Domain Entropy", "ok": ok,
            "msg": f"Normal ({entropy:.2f})" if ok else
                   f"High entropy ({entropy:.2f})"}

def check_brand_keywords(url):
    lower = url.lower()
    ext = tldextract.extract(url)
    found = [k for k in BRAND_KEYWORDS
             if k in lower and k not in ext.domain]
    return {"name": "Brand Spoofing", "ok": len(found) == 0,
            "msg": "Clean" if not found else f"Found: {', '.join(found)}"}

def check_redirects(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=5)
        hops = len(r.history)
        ok = hops < 3
        return {"name": "Redirect Chain", "ok": ok,
                "msg": f"{hops} redirect(s)" if ok else
                       f"Too many redirects ({hops})"}
    except Exception:
        return {"name": "Redirect Chain", "ok": False,
                "msg": "Could not reach URL"}

def analyze(url):
    if not url.startswith("http"):
        url = "https://" + url
    checks = [check_https(url), check_suspicious_tld(url),
              check_url_length(url), check_entropy(url),
              check_brand_keywords(url), check_redirects(url)]
    passed = sum(1 for c in checks if c["ok"])
    score = round((passed / len(checks)) * 100)
    risk = "Low" if score >= 80 else "Medium" if score >= 50 else "High"
    return {"url": url, "score": score, "risk": risk, "checks": checks}