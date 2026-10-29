
ALLOWED_CATEGORIES = {
    "Credential Harvesting",
    "Financial Scam",
    "Malware / APK Delivery",
    "Impersonation / Digital Arrest",
    "Suspicious URL",
    "Other Suspicious Activity",
    "Benign",
}


def fallback_rule_analysis(content, url_flags):
    """Analyze scam indicators using local rules only."""

    text = content.casefold()
    indicators = list(url_flags)

    rules = [
        (
            ["otp", "password", "cvv", "bank details", "pin number"],
            "Sensitive credentials or financial details are mentioned.",
        ),
        (
            [
                "blocked", "suspended", "disconnect", "immediately",
                "urgent", "24 hours", "aaj raat", "abhi",
            ],
            "Urgency or pressure language is present.",
        ),
        (
            [
                "kyc", "pan card", "aadhaar", "yono", "lottery",
                "prize", "daily earn", "digital arrest", "cbi",
            ],
            "A possible scam or impersonation theme is present.",
        ),
        (
            [
                "claim your prize", "processing fee",
                "registration fee", "pay to receive",
            ],
            "A possible reward or advance-payment lure is present.",
        ),
        (
            [".apk", "anydesk", "quicksupport", "remote access"],
            "An APK or remote-access tool is mentioned.",
        ),
    ]

    for keywords, explanation in rules:
        if any(keyword in text for keyword in keywords):
            indicators.append(explanation)

    indicators = list(dict.fromkeys(indicators))

    # Heuristic score, not a probability.
    score = min(95, len(indicators) * 25)

    if score >= 60:
        urgency = "High"
    elif score >= 30:
        urgency = "Medium"
    else:
        urgency = "Low"

    if any(word in text for word in [
        "otp", "password", "cvv", "bank details", "kyc"
    ]):
        category = "Credential Harvesting"
    elif any(word in text for word in [
        "lottery", "prize", "daily earn", "processing fee"
    ]):
        category = "Financial Scam"
    elif any(word in text for word in [
        ".apk", "anydesk", "quicksupport"
    ]):
        category = "Malware / APK Delivery"
    elif any(word in text for word in [
        "digital arrest", "cbi", "police"
    ]):
        category = "Impersonation / Digital Arrest"
    elif url_flags:
        category = "Suspicious URL"
    else:
        category = (
            "Other Suspicious Activity"
            if indicators
            else "Benign"
        )

    is_suspicious = score >= 50

    return {
        "is_phishing": is_suspicious,
        "confidence_score": score,
        "threat_category": category,
        "urgency_level": urgency,
        "suspicious_indicators": indicators or [
            "No configured warning patterns were detected."
        ],
        "safe_recommendation": (
            "Do not click unverified links, install unexpected apps, "
            "or share OTPs, passwords, PINs, or banking credentials. "
            "Verify through an official channel. Report suspected "
            "cybercrime through official Indian reporting channels."
            if is_suspicious
            else
            "No strong conclusion can be made from these rules alone. "
            "Verify the sender and destination independently."
        ),
        "analysis_source": "rules",
    }


def analyze_threat_with_ai(content, url_flags):
    """
    Compatibility wrapper for detection.py.

    No AI model is called in this version.
    """
    return fallback_rule_analysis(content, url_flags)
