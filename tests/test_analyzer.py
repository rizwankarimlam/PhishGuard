from phishguard.analyzer import analyze_email


def test_suspicious_email():
    with open("samples/suspicious_email.txt") as file:
        email = file.read()

    result = analyze_email(email)

    assert result["risk_score"] > 0
    assert result["classification"] in [
        "SUSPICIOUS", "MALICIOUS"
    ]


def test_legitimate_email():
    with open("samples/legitimate_email.txt") as file:
        email = file.read()

    result = analyze_email(email)

    assert 0 <= result["risk_score"] <= 100
