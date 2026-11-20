
import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse

URGENCY = [
    "urgent", "immediately", "act now",
    "account suspended", "verify your account",
    "password expires", "within 24 hours",
    "final warning", "limited time"
]

SENSITIVE = [
    "password", "credit card", "bank account",
    "social security", "otp", "one-time password", "pin"
]

AUTHORITY = [
    "administrator", "security team",
    "it support", "ceo", "finance department"
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "is.gd", "buff.ly"
}


def get_domain(address):
    match = re.search(
        r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
        address or ""
    )
    return match.group(1).lower() if match else ""


def extract_urls(text):
    return re.findall(
        r'https?://[^\s<>"\']+',
        text or "",
        flags=re.I
    )


def parse_email(raw):
    try:
        msg = Parser(policy=policy.default).parsestr(raw)
        body_part = msg.get_body(preferencelist=("plain",))

        body = (
            body_part.get_content()
            if body_part else raw
        )

        return {
            "From": str(msg.get("From", "")),
            "Reply-To": str(msg.get("Reply-To", "")),
            "Return-Path": str(msg.get("Return-Path", "")),
            "To": str(msg.get("To", "")),
            "Subject": str(msg.get("Subject", "")),
            "body": body
        }

    except Exception:
        return {
            "From": "",
            "Reply-To": "",
            "Return-Path": "",
            "To": "",
            "Subject": "",
            "body": raw
        }


def analyze_email(raw):

    data = parse_email(raw)
    body = data["body"] or raw
    full = raw.lower()

    findings = []
    score = 0

    def add(title, detail, points):
        nonlocal score

        findings.append({
            "title": title,
            "detail": detail,
            "points": points
        })

        score += points

    from_domain = get_domain(data["From"])
    reply_domain = get_domain(data["Reply-To"])
    return_domain = get_domain(data["Return-Path"])

    if (
        data["Reply-To"]
        and from_domain
        and reply_domain
        and from_domain != reply_domain
    ):
        add(
            "Sender and Reply-To mismatch",
            f"From domain: {from_domain}; "
            f"Reply-To domain: {reply_domain}.",
            22
        )

    if (
        data["Return-Path"]
        and from_domain
        and return_domain
        and from_domain != return_domain
    ):
        add(
            "Return-Path mismatch",
            f"From domain: {from_domain}; "
            f"Return-Path domain: {return_domain}.",
            12
        )

    urls = extract_urls(body)
    domains = set()

    for url in urls:
        try:
            host = (urlparse(url).hostname or "").lower()

            if not host:
                continue

            domains.add(host)

            if host in SHORTENERS:
                add(
                    "URL Shortener Detected",
                    f"Shortened URL found: {host}",
                    12
                )

            if host.startswith("xn--") or ".xn--" in host:
                add(
                    "Punycode Domain Detected",
                    f"Potentially deceptive hostname: {host}",
                    18
                )

            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
                add(
                    "IP Address Link",
                    f"URL points directly to IP: {host}",
                    18
                )

            if host.count("-") >= 3 or len(host) > 35:
                add(
                    "Unusual Domain Structure",
                    f"Unusual hostname: {host}",
                    8
                )

        except Exception:
            continue

    for word in URGENCY:
        if word in full:
            add(
                "Urgency Language",
                f"Pressure wording detected: {word}",
                7
            )

    for word in SENSITIVE:
        if word in full:
            add(
                "Sensitive Information Mention",
                f"Sensitive-data term detected: {word}",
                8
            )

    for word in AUTHORITY:
        if word in full:
            add(
                "Authority-related Language",
                f"Authority wording detected: {word}",
                5
            )

    risky_extensions = [
        ".exe", ".scr", ".js", ".vbs",
        ".bat", ".cmd", ".ps1", ".jar",
        ".hta", ".iso"
    ]

    for ext in risky_extensions:
        if ext in full:
            add(
                "Risky Attachment Extension",
                f"Potentially dangerous extension mentioned: {ext}",
                20
            )

    score = min(score, 100)

    if score >= 60:
        classification = "MALICIOUS"
        summary = (
            "Multiple high-risk indicators were detected. "
            "Treat this email as potentially malicious."
        )
        recommendations = [
            "Do not click any links.",
            "Do not open attachments.",
            "Never share passwords or OTPs.",
            "Report the email to your security team.",
            "Verify the sender using a separate trusted channel."
        ]

    elif score >= 20:
        classification = "SUSPICIOUS"
        summary = (
            "Warning signs were detected. "
            "Verify the sender before taking action."
        )
        recommendations = [
            "Avoid clicking unverified links.",
            "Check sender and Reply-To addresses.",
            "Visit official websites directly.",
            "Contact your IT/security team if necessary."
        ]

    else:
        classification = "SAFE"
        summary = (
            "Few obvious phishing indicators were detected. "
            "This does not guarantee that the email is safe."
        )
        recommendations = [
            "Remain cautious with unexpected links.",
            "Never share passwords or OTPs by email.",
            "Verify unusual requests independently."
        ]

    email_details = {
        "From": data["From"],
        "Reply-To": data["Reply-To"],
        "Return-Path": data["Return-Path"],
        "To": data["To"],
        "Subject": data["Subject"],
        "URLs found": ", ".join(sorted(domains)) or "None"
    }

    return {
        "risk_score": score,
        "classification": classification,
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations,
        "email_details": email_details
    }
