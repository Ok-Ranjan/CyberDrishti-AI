import os
import re

from .services.url_checker import analyze_url
from .services.ai_analyzer import (
    analyze_threat_with_ai,
    fallback_rule_analysis,
)
from .services.aikosh_engine import run_aikosh_pipeline
from .services.email_header_analyzer import analyze_email_headers


URL_PATTERN = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
)


def analyze_message(message, scan_type='general'):
    """Main detection entry point supporting multiple scan types."""
    text = message.strip()

    # Special handling for email header analysis
    if scan_type == 'email_header':
        return analyze_email_header_scan(text)

    # 1. Extract URLs from the submitted content.
    urls = list(dict.fromkeys(
        match.rstrip(".,!?;:)]}")
        for match in URL_PATTERN.findall(text)
    ))

    # 2. Analyze URLs using the existing URL checker.
    url_results = [
        analyze_url(url)
        for url in urls
    ]

    url_flags = list(dict.fromkeys(
        flag
        for item in url_results
        for flag in item.get("flags", [])
    ))

    # 3. Run the optional AI analyzer or its rule-based fallback.
    use_ai = (
        os.getenv("SCAMSHIELD_USE_AI", "false").lower() == "true"
    )

    if use_ai:
        ai_result = analyze_threat_with_ai(text, url_flags)
    else:
        ai_result = fallback_rule_analysis(text, url_flags)

    # 4. Run the AIKosh-powered Indian scam heuristic engine.
    aikosh_result = run_aikosh_pipeline(
        raw_text=text,
        extracted_urls=urls,
    )

    # 5. Calculate the transparent heuristic risk score.
    lower_text = text.lower()
    score = 0
    indicators = []

    def add_rule(points, category, explanation):
        nonlocal score
        score += points
        indicators.append({
            "category": category,
            "points": points,
            "explanation": explanation,
        })

    if re.search(
        r"\b(?:otp|password|passcode|cvv|"
        r"bank details|pin number|verification code)\b",
        lower_text,
    ):
        add_rule(
            25,
            "Sensitive information",
            "The message mentions credentials or sensitive financial information.",
        )

    if re.search(
        r"\b(?:urgent|immediately|act now|expires today|"
        r"account blocked|account suspended|disconnect)\b",
        lower_text,
    ):
        add_rule(
            15,
            "Urgency or pressure",
            "The message uses urgent or threatening language.",
        )

    if re.search(
        r"\b(?:won|winner|claim your prize|free reward|"
        r"lottery winner|cash prize|processing fee)\b",
        lower_text,
    ):
        add_rule(
            15,
            "Reward or payment lure",
            "The message contains a possible reward or advance-payment lure.",
        )

    if re.search(
        r"\b(?:apk|anydesk|quicksupport|remote access)\b",
        lower_text,
    ):
        add_rule(
            35,
            "APK or remote access",
            "The message mentions an APK or remote-access tool.",
        )

    # Score unique URL flags
    for flag in url_flags:
        add_rule(20, "URL analysis", flag)

    # Add AIKosh heuristic indicators
    aikosh_indicators = aikosh_result.get("suspicious_indicators", [])
    for explanation in aikosh_indicators:
        if explanation == "No configured warning patterns were detected.":
            continue
        indicators.append({
            "category": "AIKosh heuristic",
            "points": 0,
            "explanation": explanation,
        })

    # Add AI explanations without duplicating
    existing_explanations = {
        item["explanation"] for item in indicators
    }
    for explanation in ai_result.get("suspicious_indicators", []):
        if explanation == "No configured warning patterns were detected.":
            continue
        if explanation not in existing_explanations:
            indicators.append({
                "category": "AI assessment",
                "points": 0,
                "explanation": explanation,
            })
            existing_explanations.add(explanation)

    score = min(score, 100)

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    is_detected = (
        score >= 40
        or ai_result.get("is_phishing", False)
        or aikosh_result.get("is_phishing", False)
    )

    if aikosh_result.get("is_phishing"):
        threat_cat = aikosh_result.get("threat_category")
    elif ai_result.get("threat_category") and ai_result.get("threat_category") not in ("Benign", "No strong pattern detected"):
        threat_cat = ai_result.get("threat_category")
    elif is_detected and indicators:
        threat_cat = f"Suspicious Activity ({indicators[0]['category']})"
    else:
        threat_cat = "No strong pattern detected"

    return {
        "score": score,
        "risk_level": risk_level,
        "scan_type": scan_type,
        "indicators": indicators,
        "urls": url_results,
        "is_phishing": is_detected,
        "threat_category": threat_cat,
        "ai_confidence": ai_result.get("confidence_score", 0),
        "analysis_source": (
            f"{ai_result.get('analysis_source', 'rules')} "
            "+ aikosh_heuristics"
        ),
        "aikosh_result": aikosh_result,
        "safe_recommendation": (
            aikosh_result.get("safe_recommendation")
            if aikosh_result.get("is_phishing")
            else ai_result.get(
                "safe_recommendation",
                "Verify the sender independently before taking action.",
            )
        ),
        "message": (
            "Configured warning indicators were detected."
            if score > 0 or aikosh_result.get("is_phishing")
            else "No configured warning indicators were detected."
        ),
    }


def analyze_email_header_scan(raw_headers):
    """Dedicated analysis path for email headers."""
    header_result = analyze_email_headers(raw_headers)

    indicators = []
    for explanation in header_result.get('suspicious_indicators', []):
        if explanation == 'No suspicious header patterns were detected.':
            continue
        indicators.append({
            'category': 'Email Header Analysis',
            'points': 10,
            'explanation': explanation,
        })

    return {
        'score': header_result['confidence_score'],
        'risk_level': header_result['risk_level'],
        'scan_type': 'email_header',
        'indicators': indicators,
        'urls': [],
        'is_phishing': header_result['is_phishing'],
        'threat_category': header_result['threat_category'],
        'ai_confidence': header_result['confidence_score'],
        'analysis_source': 'email_header_rules + aikosh_heuristics',
        'aikosh_result': {
            'risk_level': header_result['risk_level'],
            'aikosh_metadata': {
                'platform': 'AIKosh (aikosh.indiaai.gov.in)',
                'note': 'Email header analysis uses local rules.',
            },
        },
        'safe_recommendation': header_result['safe_recommendation'],
        'message': (
            'Suspicious email header patterns were detected.'
            if header_result['is_phishing']
            else 'No suspicious header patterns were detected.'
        ),
        'header_details': header_result.get('header_details', {}),
    }
