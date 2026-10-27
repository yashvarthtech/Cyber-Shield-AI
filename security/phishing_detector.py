"""Transparent local heuristics. These rules are indicators, not proof of a scam."""
import re

PATTERNS = [
    ("urgent language", re.compile(r"\b(urgent|immediately|act now|within 24 hours|final warning|today only)\b", re.I), 1),
    ("account threat", re.compile(r"\b(account (will be|has been) (blocked|suspended|locked)|account closure|verify your account)\b", re.I), 2),
    ("credential request", re.compile(r"\b(password|passcode|OTP|one[- ]time password|PIN|login details)\b", re.I), 2),
    ("payment pressure", re.compile(r"\b(pay now|processing fee|claim your prize|gift card|wire transfer|payment required)\b", re.I), 2),
    ("prize or too-good-to-be-true claim", re.compile(r"\b(you (have )?won|winner selected|free money|guaranteed reward)\b", re.I), 1),
    ("link included", re.compile(r"https?://|www\.", re.I), 1),
    ("impersonation wording", re.compile(r"\b(bank support|IT department|customer support|delivery failed)\b", re.I), 1),
]


def analyze_text_rules(text):
    indicators = []
    score = 0
    for label, pattern, weight in PATTERNS:
        if pattern.search(text or ""):
            indicators.append(label)
            score += weight
    if score >= 5:
        risk = "High"
    elif score >= 2:
        risk = "Medium"
    else:
        risk = "Low"
    if not text:
        risk = "Inconclusive"
    return {
        "risk_level": risk,
        "category": "Potential phishing / social engineering" if indicators else "No common phishing indicators found",
        "indicators": indicators,
        "score": score,
        "explanation": (
            "The local checker found one or more common warning signs." if indicators
            else "The local checker found no matching warning signs. This does not prove the message is safe."
        ),
        "recommended_actions": [
            "Do not share passwords, PINs, or OTPs.",
            "Verify unexpected requests using the official app or a known contact method.",
            "Avoid clicking links in unexpected messages."
        ] if indicators else [
            "Check the sender and context carefully.",
            "Do not treat a low score as proof that the message is legitimate."
        ]
    }
