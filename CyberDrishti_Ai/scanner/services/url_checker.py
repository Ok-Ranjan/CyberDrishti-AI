
import ipaddress
import re
from urllib.parse import urlsplit


SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online",
    "work", "click", "live", "link",
}

TARGET_BRANDS = {
    "sbi", "hdfc", "icici", "paytm",
    "google", "amazon", "netflix", "incometax",
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
    # Look for brand-like labels and check whether the domain is an
    # exact brand domain or a subdomain of that brand domain.
    known_brand_domains = {
        "sbi.co.in",
        "hdfcbank.com",
        "icicibank.com",
        "paytm.com",
        "google.com",
        "amazon.com",
        "netflix.com",
        "incometax.gov.in",
    }

    labels_set = set(labels)

    for brand in TARGET_BRANDS:
        if brand not in labels_set:
            continue

        is_known_domain = any(
            hostname == known or hostname.endswith("." + known)
            for known in known_brand_domains
            if known.split(".")[0] == brand
            or brand in known.split(".")
        )

        if not is_known_domain:
            flags.append(
                f"The hostname contains the brand-like label '{brand}'. "
                "Verify the actual domain before trusting it."
            )

    # Avoid duplicate findings.
    flags = list(dict.fromkeys(flags))

    return {
        "url": url,
        "domain": hostname,
        "flags": flags,
        "is_suspicious": bool(flags),
    }
