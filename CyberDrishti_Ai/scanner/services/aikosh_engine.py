import re
import ipaddress
from urllib.parse import urlsplit
from typing import Any


# These are proposed model references from your draft.
# They are metadata only until actual model inference is configured.
AIKOSH_MODELS = {
    "translation": "AI4Bharat/indictrans2-indic-en-1B",
    "reasoner": "ProjectMosiacAI/Hades-2.0-Night3-8k",
    "anti_fraud_head": "AIKosh/Samadhan-Bharat-Sovereign-Dual-Head",
    "benchmark_dataset": "AIKosh/National-1M-Anti-Fraud-Atlas",
}


AUTHORITY_KEYWORDS = {
    "Electricity / Utility": [
        "electricity", "power bill", "bijli", "light bill",
        "mseb", "uppcl", "bescom",
    ],
    "Banking": [
        "sbi", "yono", "hdfc", "icici", "pnb",
        "bank account", "kyc", "pan card",
    ],
    "Law Enforcement / Digital Arrest": [
        "cbi", "police", "customs", "mumbai police",
        "narcotics", "digital arrest",
    ],
    "Telecom": [
        "trai", "sim card", "mobile number blocked", "esim",
    ],
}

FINANCIAL_KEYWORDS = [
    "upi", "gpay", "phonepe", "paytm", "refund",
    "lottery", "kbc", "cashback",
]

APK_KEYWORDS = [
    ".apk", "download app", "install quicksupport",
    "anydesk", "remote access",
]

URGENCY_KEYWORDS = [
    "aaj raat", "tonight", "immediately",
    "within 2 hours", "account blocked",
    "arrest", "urgent", "immediately verify",
]

CREDENTIAL_KEYWORDS = [
    "share your otp", "enter otp", "send otp",
    "share password", "enter your password",
    "mpin", "cvv", "card pin",
]


def detect_language_is_indic(text: str) -> bool:
    """Detect common Indic Unicode scripts; this is not full language identification."""
    return bool(
        re.search(
            r"[\u0900-\u097F\u0980-\u09FF\u0A00-\u0A7F"
            r"\u0A80-\u0AFF\u0B00-\u0B7F\u0B80-\u0BFF"
            r"\u0C00-\u0C7F\u0C80-\u0CFF\u0D00-\u0D7F]",
            text,
        )
    )


def translate_indic_to_english(text: str) -> str:
    """
    Placeholder until a real translation model/API is configured.
    Never claims that translation occurred.
    """
    return text


def contains_keyword(text: str, keyword: str) -> bool:
    """Avoid matching short keywords inside unrelated words."""
    if re.fullmatch(r"[a-z0-9 ]+", keyword):
        pattern = r"(?<!\w)" + re.escape(keyword) + r"(?!\w)"
        return re.search(pattern, text, flags=re.IGNORECASE) is not None

    return keyword.casefold() in text.casefold()


def extract_indian_scam_entities(text: str) -> dict[str, Any]:
    text_lower = text.casefold()

    authority = None
    for category, keywords in AUTHORITY_KEYWORDS.items():
        if any(contains_keyword(text_lower, word) for word in keywords):
            authority = category
            break

    urgency = [
        word for word in URGENCY_KEYWORDS
        if contains_keyword(text_lower, word)
    ]

    return {
        "targeted_authority": authority,
        "is_upi_or_financial": any(
            contains_keyword(text_lower, word)
            for word in FINANCIAL_KEYWORDS
        ),
        "is_apk_download": any(
            contains_keyword(text_lower, word)
            for word in APK_KEYWORDS
        ),
        "requests_credentials": any(
            contains_keyword(text_lower, word)
            for word in CREDENTIAL_KEYWORDS
        ),
        "urgency_triggers": urgency,
    }


def inspect_url(url: str) -> list[str]:
    """
    Local URL parsing only. Does not visit or download the URL.
    These signals are warnings, not proof that a site is malicious.
    """
    flags = []
    candidate = url.strip().rstrip(".,);]")

    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname

        if not hostname:
            return ["URL could not be parsed safely"]

        hostname = hostname.casefold()

        try:
            ipaddress.ip_address(hostname)
            flags.append("URL uses an IP address instead of a domain name")
        except ValueError:
            pass

        if hostname.startswith("xn--") or ".xn--" in hostname:
            flags.append("URL contains an internationalized/punycode domain")

        if hostname.count(".") >= 4:
            flags.append("URL has an unusually deep subdomain structure")

        if parsed.scheme.casefold() != "https":
            flags.append("URL does not use HTTPS")

        if "@" in parsed.netloc:
            flags.append("URL contains an @ symbol in its authority section")

    except (ValueError, UnicodeError):
        flags.append("URL could not be parsed safely")

    return flags


def run_aikosh_pipeline(
    raw_text: str,
    extracted_urls: list[str] | None = None,
) -> dict[str, Any]:
    """
    Heuristic Indian scam assessment.
    This version does not invoke AIKosh models yet.
    """
    extracted_urls = extracted_urls or []
    entities = extract_indian_scam_entities(raw_text)

    indicators: list[str] = []
    score = 0

    if entities["targeted_authority"]:
        indicators.append(
            f"Authority reference detected: "
            f"{entities['targeted_authority']}. Verify the sender independently."
        )
        score += 15

    if entities["urgency_triggers"]:
        indicators.append(
            "Urgency language detected: "
            + ", ".join(entities["urgency_triggers"])
        )
        score += 20

    if entities["is_apk_download"]:
        indicators.append(
            "APK or remote-access software reference detected. "
            "Do not install an app at a stranger's request."
        )
        score += 35

    if entities["is_upi_or_financial"]:
        indicators.append(
            "Financial or payment-related wording detected. "
            "Verify any payment or refund independently."
        )
        score += 10

    if entities["requests_credentials"]:
        indicators.append(
            "Possible request for sensitive credentials, PIN, or OTP detected."
        )
        score += 35

    for url in extracted_urls:
        for flag in inspect_url(url):
            indicators.append(f"{flag}: {url}")
            score += 15

    # Cap the heuristic score. It is not a model probability.
    score = min(score, 100)

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    is_scam = score >= 45

    if is_scam:
        recommendation = (
            "Do not click links, install APK files, or share OTPs, PINs, "
            "or passwords. Verify through the organization's official "
            "website or phone number. In India, suspected cybercrime can "
            "be reported at cybercrime.gov.in or helpline 1930."
        )
    else:
        recommendation = (
            "No strong warning pattern was detected by these rules. "
            "This does not prove the message is safe. Verify the sender "
            "independently and never share OTPs, PINs, or passwords."
        )

    return {
        "is_phishing": is_scam,
        "confidence_score": score,
        "risk_score": score,
        "risk_level": risk_level,
        "threat_category": (
            "Possible " + entities["targeted_authority"] + " impersonation"
            if entities["targeted_authority"] and is_scam
            else "Possible phishing/scam"
            if is_scam
            else "No strong pattern detected"
        ),
        "urgency_level": (
            "High" if entities["urgency_triggers"] else "Low"
        ),
        "suspicious_indicators": list(dict.fromkeys(indicators)) or [
            "No configured warning patterns were detected."
        ],
        "safe_recommendation": recommendation,
        "analysis_source": "heuristics",
        "translation_performed": False,
        "aikosh_metadata": {
            "configured_model_references": AIKOSH_MODELS,
            "models_actually_invoked": [],
        },
    }