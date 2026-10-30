"""
Email header spam/phishing analyzer.

Examines raw email headers for common spam and spoofing signals.
This is a rule-based heuristic engine — it does not call external APIs.
"""

import re
from typing import Any


# Known freemail providers often used in phishing
FREEMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'aol.com', 'mail.com', 'protonmail.com', 'yandex.com',
    'zoho.com', 'gmx.com', 'icloud.com',
}

# Suspicious header patterns
SPAM_HEADER_SIGNALS = [
    (r'X-Spam-Status:\s*Yes', 'X-Spam-Status header indicates spam.'),
    (r'X-Spam-Flag:\s*YES', 'X-Spam-Flag is set to YES.'),
    (r'X-Spam-Score:\s*([5-9]|[1-9]\d)', 'High X-Spam-Score detected.'),
    (r'Authentication-Results:.*dkim=fail', 'DKIM authentication failed.'),
    (r'Authentication-Results:.*spf=fail', 'SPF authentication failed.'),
    (r'Authentication-Results:.*spf=softfail', 'SPF soft-fail detected.'),
    (r'Authentication-Results:.*dmarc=fail', 'DMARC authentication failed.'),
    (r'X-Mailer:\s*(PHPMailer|swiftmailer|mass.mailer)', 'Suspicious X-Mailer detected (mass mailer).'),
    (r'Received:.*\[(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.', 'Received from private/internal IP — may indicate relay abuse.'),
    (r'Reply-To:.*(?!From:)', 'Reply-To differs from From — potential spoofing.'),
    (r'X-Originating-IP:', 'X-Originating-IP header present — message sent from webmail or external client.'),
    (r'Content-Type:.*multipart/mixed.*name=.*\.(?:exe|scr|bat|cmd|pif|vbs|js)', 'Dangerous attachment type detected in headers.'),
    (r'List-Unsubscribe:', 'List-Unsubscribe header present — likely bulk/marketing email.'),
]


def extract_header_field(headers: str, field: str) -> str | None:
    """Extract the value of a specific header field."""
    pattern = rf'^{re.escape(field)}:\s*(.+?)$'
    match = re.search(pattern, headers, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None


def analyze_email_headers(raw_headers: str) -> dict[str, Any]:
    """
    Analyze raw email headers for spam/phishing indicators.
    Returns a result dict compatible with the main detection pipeline.
    """
    indicators: list[str] = []
    score = 0

    # Check each spam signal pattern
    for pattern, description in SPAM_HEADER_SIGNALS:
        if re.search(pattern, raw_headers, re.IGNORECASE | re.MULTILINE):
            indicators.append(description)
            score += 15

    # Check From header for freemail in business context
    from_header = extract_header_field(raw_headers, 'From')
    if from_header:
        email_match = re.search(r'[\w.+-]+@([\w.-]+)', from_header)
        if email_match:
            domain = email_match.group(1).lower()
            if domain in FREEMAIL_DOMAINS:
                # Check if subject suggests business/official communication
                subject = extract_header_field(raw_headers, 'Subject') or ''
                business_words = ['invoice', 'payment', 'account', 'verify', 'bank', 'kyc', 'urgent', 'tax']
                if any(word in subject.lower() for word in business_words):
                    indicators.append(
                        f'Business-themed email from freemail domain ({domain}) — potential spoofing.'
                    )
                    score += 20

    # Check for missing critical headers
    critical_headers = ['From', 'Date', 'Message-ID']
    for header in critical_headers:
        if not extract_header_field(raw_headers, header):
            indicators.append(f'Missing critical header: {header}')
            score += 10

    # Check for multiple Received headers (excessive relaying)
    received_count = len(re.findall(r'^Received:', raw_headers, re.MULTILINE | re.IGNORECASE))
    if received_count > 8:
        indicators.append(f'Excessive mail relays detected ({received_count} hops) — unusual routing.')
        score += 10

    # Check for encoding tricks in Subject
    subject = extract_header_field(raw_headers, 'Subject') or ''
    if re.search(r'=\?.*\?[BQ]\?', subject):
        # Encoded subject — not inherently bad but worth noting if other signals present
        if score > 0:
            indicators.append('Subject uses MIME encoding — may obscure content from filters.')
            score += 5

    score = min(score, 100)

    if score >= 60:
        risk_level = 'High'
    elif score >= 30:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'

    is_spam = score >= 45

    return {
        'is_phishing': is_spam,
        'is_spam': is_spam,
        'confidence_score': score,
        'risk_level': risk_level,
        'threat_category': 'Email Header Spam/Spoofing' if is_spam else 'No strong pattern detected',
        'suspicious_indicators': indicators or ['No suspicious header patterns were detected.'],
        'safe_recommendation': (
            'This email shows signs of spam or spoofing. Do not click links or '
            'download attachments. Verify the sender through official channels.'
            if is_spam
            else 'No strong spam signals were detected in the headers. '
                 'However, header analysis alone cannot guarantee safety.'
        ),
        'analysis_source': 'email_header_rules',
        'header_details': {
            'from': from_header,
            'subject': subject,
            'received_hops': received_count,
        },
    }
