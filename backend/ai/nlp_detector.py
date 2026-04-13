import re

# ===== ADVANCED PHISHING TEXT ANALYSIS =====

SUSPICIOUS_PATTERNS = [
    r"verify.*account",
    r"login.*urgent",
    r"update.*payment",
    r"confirm.*identity",
    r"bank.*alert",
    r"account.*suspended",
    r"click.*verify",
    r"enter.*otp",
    r"security.*alert",
    r"unusual.*activity"
]

def detect_phishing_text(text: str):
    score = 0
    reasons = []

    text = text.lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text):
            score += 10
            reasons.append(pattern)

    # aggressive phrases
    if "urgent" in text or "immediately" in text:
        score += 10
        reasons.append("urgency detected")

    if "limited time" in text:
        score += 10
        reasons.append("pressure tactic")

    return score, reasons