"""Offline URL string checks only. This module never opens or fetches a URL."""
import re
from urllib.parse import urlparse
import ipaddress


SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at"}
SUSPICIOUS_TERMS = ("login", "verify", "secure", "account", "update", "password", "wallet", "payment", "free")


def analyze_url(value):
    value = (value or "").strip()
    if not value:
        return None
    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or " " in host:
            raise ValueError("Invalid host")
    except Exception:
        return {
            "risk_level": "Inconclusive",
            "category": "URL could not be parsed",
            "indicators": ["invalid or incomplete URL"],
            "explanation": "The input could not be parsed as a URL. No network request was made."
        }

    indicators = []
    try:
        ipaddress.ip_address(host)
        indicators.append("uses an IP address instead of a typical domain name")
    except ValueError:
        pass
    if host in SHORTENERS:
        indicators.append("uses a known URL-shortening domain")
    if "@" in parsed.netloc:
        indicators.append("contains an @ symbol in the authority section")
    if host.startswith("xn--") or ".xn--" in host:
        indicators.append("contains an internationalized/punycode domain label")
    if len(host) > 45:
        indicators.append("unusually long hostname")
    if host.count("-") >= 3:
        indicators.append("multiple hyphens in hostname")
    if re.search(r"%[0-9a-fA-F]{2}", parsed.path):
        indicators.append("contains percent-encoded path characters")
    if any(term in (host + parsed.path.lower()) for term in SUSPICIOUS_TERMS):
        indicators.append("contains a security-sensitive term (context matters)")
    if parsed.scheme.lower() != "https":
        indicators.append("does not use HTTPS")

    # This score is deliberately simple and should not be described as a reputation verdict.
    high_signal = {"uses an IP address instead of a typical domain name", "contains an @ symbol in the authority section", "contains an internationalized/punycode domain label"}
    score = sum(2 if item in high_signal else 1 for item in indicators)
    risk = "High" if score >= 4 else "Medium" if score >= 2 else "Low"
    return {
        "risk_level": risk,
        "category": "URL structure review",
        "host": host,
        "indicators": indicators,
        "score": score,
        "explanation": "These are URL-string heuristics only. The app did not visit the site and has no live reputation verdict.",
        "recommended_actions": [
            "Do not enter passwords or payment information unless you independently verify the domain.",
            "Open the service's official app or type its known address yourself.",
            "Remember that HTTPS alone does not prove a site is trustworthy."
        ]
    }
