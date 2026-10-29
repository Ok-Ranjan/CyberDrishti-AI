import re
import urllib.parse

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.online', '.work', '.click', '.live', '.link']
TARGET_BRANDS = ['sbi', 'hdfc', 'icici', 'paytm', 'google', 'amazon', 'netflix', 'incometax']

def analyze_url(url: str) -> dict:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    
    flags = []
    # 1. Check IP address as host
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        flags.append("Domain is a raw IP address (Major phishing indicator)")
        
    # 2. Check for suspicious cheap TLDs
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append(f"Domain uses high-risk TLD: {domain}")
        
    # 3. Check for Brand Typosquatting (e.g., sbi-kyc-update.com)
    for brand in TARGET_BRANDS:
        if brand in domain and not domain.endswith(f"{brand}.co.in") and not domain.endswith(f"{brand}.com"):
            flags.append(f"Possible brand spoofing detected for: '{brand.upper()}'")
            
    # 4. Check excessive hyphens or subdomains
    if domain.count('.') > 3 or domain.count('-') > 2:
        flags.append("Abnormal number of subdomains/hyphens used to disguise origin")
        
    return {
        "url": url,
        "domain": domain,
        "flags": flags,
        "is_suspicious": len(flags) > 0
    }