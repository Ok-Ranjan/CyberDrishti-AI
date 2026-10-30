
import ipaddress
import re
from urllib.parse import urlsplit


SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online",
    "work", "click", "live", "link",
}

TARGET_BRANDS = {
    "sbi", "hdfc", "icici", "paytm", "phonepe", "gpay",
    "google", "amazon", "netflix", "incometax", "jio", "airtel",
}


def analyze_url(url: str) -> dict:
    url = url.strip()
    flags = []

    if not url:
        return {
            "url": url,
            "domain": "",
            "flags": [],
            "is_suspicious": False,
        }

    # Support URLs submitted without a scheme.
    candidate = url if "://" in url else f"https://{url}"

    try:
        parsed = urlsplit(candidate)

        # Reject unsupported schemes and malformed URLs.
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Unsupported URL scheme")

        if not parsed.hostname:
            raise ValueError("Missing hostname")

        hostname = parsed.hostname.rstrip(".").lower()

        # Validate the optional port if present.
        _ = parsed.port

    except ValueError:
        return {
            "url": url,
            "domain": "",
            "flags": ["URL is malformed or uses an unsupported format."],
            "is_suspicious": True,
        }

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        flags.append(
            "The URL uses an IP address as its host."
        )

    # Apply domain rules to the hostname, not the entire URL.
    labels = hostname.split(".")
    tld = labels[-1] if len(labels) > 1 else ""

    if tld in SUSPICIOUS_TLDS:
        flags.append(
            f"The domain uses the TLD '.{tld}', which merits review."
        )

    if hostname.count(".") > 3 or hostname.count("-") > 2:
        flags.append(
            "The hostname contains many subdomains or hyphens."
        )

    # A brand appearing inside a hostname does not prove impersonation.
    # Look for brand-like tokens (splitting on dots and hyphens)
    known_brand_domains = {
        "sbi.co.in",
        "hdfcbank.com",
        "icicibank.com",
        "paytm.com",
        "phonepe.com",
        "google.com",
        "amazon.com",
        "netflix.com",
        "incometax.gov.in",
        "airtel.in",
        "jio.com",
    }

    tokens = set(re.split(r"[.-]", hostname))

    for brand in TARGET_BRANDS:
        if brand not in tokens:
            continue

        is_known_domain = any(
            hostname == known or hostname.endswith("." + known)
            for known in known_brand_domains
            if brand in known
        )

        if not is_known_domain:
            flags.append(
                f"The hostname contains the brand-like keyword '{brand}'. "
                "Possible brand impersonation spoofing."
            )

    # Avoid duplicate findings.
    flags = list(dict.fromkeys(flags))

    return {
        "url": url,
        "domain": hostname,
        "flags": flags,
        "is_suspicious": bool(flags),
    }
