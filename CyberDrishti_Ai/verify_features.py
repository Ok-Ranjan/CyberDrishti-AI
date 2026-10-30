import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "CyberDrishti_Ai.settings")
django.setup()

from django.test import Client
from scanner.models import ScanHistory
from scanner.detection import analyze_message
from scanner.services.aikosh_engine import AIKOSH_MODELS
import json

def test_all():
    print("=" * 60)
    print("CYBERDRISHTI AI — HACKATHON FEATURE VERIFICATION")
    print("=" * 60)

    # 1. Verify AIKosh Models Registration
    print("\n[1] Verifying AIKosh Model References...")
    assert len(AIKOSH_MODELS) >= 4, "Missing AIKosh models"
    for key, model in AIKOSH_MODELS.items():
        print(f"  [OK] Found AIKosh Model '{model['name']}' (ID: {model['id']})")
    print("  -> AIKosh Model Registry verified successfully.")

    # 2. Verify Detection Engine for All Threat Vectors
    print("\n[2] Verifying Detection Engine Channels...")

    # A. SMS Phishing
    sms_text = "Dear SBI User, your YONO account has been suspended! Click http://sbi-kyc-update.xyz to verify PAN immediately or electricity will be cut off tonight."
    res_sms = analyze_message(sms_text, scan_type='sms')
    print(f"  [OK] SMS Scan: Score={res_sms['score']}/100, Risk={res_sms['risk_level']}, Threat='{res_sms['threat_category']}'")
    assert res_sms['is_phishing'] is True, "SMS should be detected as phishing"

    # B. WhatsApp Scam / Remote Access APK
    wa_text = "URGENT: CBI Police Digital Arrest Notice. Download CBI-Verification.apk via AnyDesk and share OTP immediately."
    res_wa = analyze_message(wa_text, scan_type='whatsapp')
    print(f"  [OK] WhatsApp Scan: Score={res_wa['score']}/100, Risk={res_wa['risk_level']}, Category='{res_wa['threat_category']}'")
    assert res_wa['is_phishing'] is True, "WhatsApp scam should be detected"

    # C. URL Detection (IP Host & Suspicious TLD)
    url_text = "Check your prize at http://192.168.1.100/free-lottery-gift.top"
    res_url = analyze_message(url_text, scan_type='url')
    print(f"  [OK] URL Scan: Score={res_url['score']}/100, Risk={res_url['risk_level']}, URLs detected={len(res_url['urls'])}")
    assert len(res_url['urls']) > 0, "URL should be detected"

    # D. Email Header Spam / Spoofing Detection
    email_headers = """From: "SBI Security" <security-alerts@gmail.com>
Subject: URGENT: Verify your bank invoice and account details
X-Spam-Status: Yes
Authentication-Results: mx.google.com; dkim=fail; spf=fail
Received: from unknown (HELO evil-relay.xyz) (10.0.0.5)
"""
    res_headers = analyze_message(email_headers, scan_type='email_header')
    print(f"  [OK] Email Header Spam Scan: Score={res_headers['score']}/100, Risk={res_headers['risk_level']}, Threat='{res_headers['threat_category']}'")
    assert res_headers['is_phishing'] is True or res_headers['score'] >= 45, "Email header spam should be flagged"

    # E. Benign / Safe Message
    benign_text = "Hi Rahul, let's meet tomorrow for hackathon project preparation at the library."
    res_benign = analyze_message(benign_text, scan_type='general')
    print(f"  [OK] Benign Message Scan: Score={res_benign['score']}/100, Risk={res_benign['risk_level']}")
    assert res_benign['risk_level'] == 'Low', "Benign message should be Low risk"

    # 3. Verify Django Web Views & 3 Pages (Home, Detection/Result, History)
    print("\n[3] Verifying Django 3 Pages & Endpoints with Test Client...")
    client = Client()

    # Page 1: Home Page (GET)
    res_home = client.get('/')
    assert res_home.status_code == 200, f"Home page returned {res_home.status_code}"
    assert b"CyberDrishti" in res_home.content, "Home page missing brand"
    assert b"Detection Type" in res_home.content, "Home page missing scan type selector"
    print("  [OK] PAGE 1 (Home): Status 200 OK, form rendered.")

    # Page 2: Detection / Result Page (POST to submit scan)
    initial_count = ScanHistory.objects.count()
    res_post = client.post('/', {
        'scan_type': 'email_header',
        'message': email_headers
    })
    assert res_post.status_code == 200, f"Submit scan returned {res_post.status_code}"
    assert b"Detection Results" in res_post.content, "Result page missing heading"
    assert b"Email Header Spam Analysis" in res_post.content, "Header scan type missing in result"
    assert b"AIKosh Model References" in res_post.content, "AIKosh section missing in result"
    new_count = ScanHistory.objects.count()
    assert new_count == initial_count + 1, "Scan should be saved to database"
    latest_scan = ScanHistory.objects.first()
    print(f"  [OK] PAGE 2 (Detection/Result): Status 200 OK, scan evaluated & saved to DB (ID: {latest_scan.id}).")

    # Page 3: History Page (GET)
    res_hist = client.get('/history/')
    assert res_hist.status_code == 200, f"History page returned {res_hist.status_code}"
    assert b"Scan History" in res_hist.content, "History heading missing"
    assert b"Total Scans" in res_hist.content, "Stats cards missing"
    assert str(latest_scan.id).encode() in res_hist.content or b"Email Header" in res_hist.content, "Latest scan should appear in history table"
    print(f"  [OK] PAGE 3 (History): Status 200 OK, statistics & history table rendered.")

    # Detail View of a Scan from History
    res_detail = client.get(f'/history/{latest_scan.id}/')
    assert res_detail.status_code == 200, f"Detail page returned {res_detail.status_code}"
    assert b"Viewing from history" in res_detail.content, "Detail page missing history badge"
    print(f"  [OK] Scan Detail View: Status 200 OK for Scan ID {latest_scan.id}.")

    # API Endpoint: /api/scan/ (POST)
    api_payload = json.dumps({
        "scan_type": "whatsapp",
        "message": "Click here to claim 50000 Rs cashback on PhonePe: http://cashback-phonepe.club"
    })
    res_api = client.post('/api/scan/', data=api_payload, content_type='application/json')
    assert res_api.status_code == 200, f"API returned {res_api.status_code}"
    api_data = res_api.json()
    assert api_data.get('is_phishing') is True, "API should detect phishing"
    print(f"  [OK] JSON API (/api/scan/): Status 200 OK, Score={api_data['score']}, Phishing={api_data['is_phishing']}.")

    print("\n" + "=" * 60)
    print("ALL VERIFICATION CHECKS PASSED SUCCESSFULLY! (100% READY)")
    print("=" * 60)

if __name__ == "__main__":
    test_all()
