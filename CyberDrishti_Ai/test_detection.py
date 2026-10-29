
from pprint import pprint

from scanner.detection import analyze_message


samples = [
    (
        "OTP scam",
        "Your bank account is blocked. Share your OTP immediately "
        "to complete KYC.",
    ),
    (
        "APK scam",
        "Install this APK using AnyDesk to receive your electricity refund.",
    ),
    (
        "Ordinary message",
        "Hi, I will meet you at college tomorrow at 10 AM.",
    ),
    (
        "Suspicious URL",
        "Verify your account at http://192.0.2.1/login immediately.",
    ),
]

for name, message in samples:
    print(f"\n{'=' * 50}\nTEST: {name}")
    try:
        result = analyze_message(message)
        pprint(result)
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
