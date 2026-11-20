from __future__ import annotations
from dataclasses import dataclass, asdict
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse
import re
import json

URGENCY = {
    "urgent": 8, "immediately": 8, "act now": 8, "within 24 hours": 7,
    "account locked": 8, "suspended": 6, "final warning": 8, "verify now": 7,
    "payment failed": 5, "overdue": 5, "expire": 4, "expires": 4,
}
AUTHORITY = {
    "ceo": 5, "director": 5, "it support": 5, "administrator": 5,
    "human resources": 4, "hr department": 4, "government": 4,
    "security team": 4, "bank": 3,
}
FEAR_REWARD = {
    "legal action": 7, "lawsuit": 7, "penalty": 5, "your account will be closed": 8,
    "prize": 4, "winner": 4, "claim your reward": 6, "free gift": 4,
    "refund": 3, "unusual activity": 4,
}
SENSITIVE = {
    "password": 6, "one-time password": 8, "otp": 8, "mfa code": 8,
    "credit card": 7, "bank details": 7, "payment details": 6,
    "login credentials": 8, "recovery code": 8,
}
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat",
                        ".cmd", ".ps1", ".hta", ".iso", ".img", ".lnk", ".msi"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
BRANDS = {"google": {"google.com"}, "microsoft": {"microsoft.com", "live.com", "outlook.com"},
          "paypal": {"paypal.com"}, "amazon": {"amazon.com"}, "facebook": {"facebook.com"}}

@dataclass
class Finding:
    category: str
    severity: str
    points: int
    evidence: str
    explanation: str

@dataclass
class Analysis:
    subject: str
    sender: str
    classification: str
    risk_score: int
    findings: list[dict]
    recommended_action: str
    limitations: list[str]

def extract_eml(path: Path) -> dict:
    with path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    body_parts, attachments = [], []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
            elif part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            pass
    return {
        "subject": str(msg.get("Subject", "")),
        "sender": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "return_path": str(msg.get("Return-Path", "")),
        "body": "\n".join(map(str, body_parts)),
        "attachments": attachments,
    }

def _domain_from_address(value: str) -> str:
    match = re.search(r'@([A-Za-z0-9.-]+)', value or "")
    return match.group(1).lower().strip(".") if match else ""

def _urls(text: str) -> list[str]:
    found = re.findall(r'https?://[^\s<>"\']+', text or "", flags=re.I)
    return [u.rstrip(".,);]") for u in found]

def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""

def _brand_lookalike(host: str) -> str | None:
    for brand, official_domains in BRANDS.items():
        if brand in host and host not in official_domains and not any(host.endswith("." + d) for d in official_domains):
            return brand
    return None

def analyze_message(data: dict) -> Analysis:
    subject = str(data.get("subject", ""))
    sender = str(data.get("sender", ""))
    reply_to = str(data.get("reply_to", ""))
    return_path = str(data.get("return_path", ""))
    body = str(data.get("body", ""))
    attachments = list(data.get("attachments", []) or [])
    combined = f"{subject}\n{body}"
    lower = combined.lower()
    findings: list[Finding] = []

    def add(category, severity, points, evidence, explanation):
        findings.append(Finding(category, severity, points, evidence, explanation))

    sender_domain = _domain_from_address(sender)
    reply_domain = _domain_from_address(reply_to)
    return_domain = _domain_from_address(return_path)
    if reply_domain and sender_domain and reply_domain != sender_domain:
        add("Header mismatch", "high", 18, f"From domain: {sender_domain}; Reply-To domain: {reply_domain}",
            "Replies may be redirected to a different domain. Verify through a trusted channel.")
    if return_domain and sender_domain and return_domain != sender_domain:
        add("Header mismatch", "medium", 10, f"From domain: {sender_domain}; Return-Path domain: {return_domain}",
            "The envelope return path differs from the visible sender. This can be legitimate, but needs review.")

    for phrase, points in URGENCY.items():
        if phrase in lower:
            add("Urgency", "medium", points, phrase, "Urgency can pressure recipients into acting before verifying a request.")
    for phrase, points in AUTHORITY.items():
        if phrase in lower:
            add("Authority impersonation", "medium", points, phrase, "Attackers may impersonate trusted roles to discourage verification.")
    for phrase, points in FEAR_REWARD.items():
        if phrase in lower:
            add("Fear or reward manipulation", "medium", points, phrase, "Threats or unexpected rewards are common social-engineering lures.")
    for phrase, points in SENSITIVE.items():
        if phrase in lower:
            add("Sensitive information request", "high", points, phrase, "Never disclose passwords, OTPs, recovery codes, or payment data through an unsolicited message.")

    urls = _urls(combined)
    for url in urls:
        host = _host(url)
        if not host:
            add("Malformed URL", "medium", 8, url, "The URL could not be parsed reliably. Do not open it.")
            continue
        if host in SHORTENERS:
            add("URL shortener", "medium", 10, host, "A shortened URL hides its final destination. Verify it safely before use.")
        if "xn--" in host:
            add("Punycode domain", "high", 15, host, "Punycode may represent international characters that resemble trusted letters.")
        brand = _brand_lookalike(host)
        if brand:
            add("Lookalike domain", "high", 20, host, f"The hostname contains '{brand}' but is not an identified official domain.")
        if host.count("-") >= 2 or len(host.split(".")) >= 5:
            add("Unusual domain structure", "low", 5, host, "Multiple hyphens or deeply nested labels deserve closer inspection.")
        if urlparse(url).username or urlparse(url).password:
            add("URL credential trick", "high", 18, url, "Credentials embedded before the @ symbol can disguise the actual destination.")

    for name in attachments:
        suffix = Path(name).suffix.lower()
        if suffix in DANGEROUS_EXTENSIONS:
            add("Risky attachment", "high", 20, name, f"The {suffix} extension can execute code or mount potentially dangerous content.")
        elif suffix in {".html", ".htm", ".zip", ".rar", ".7z"}:
            add("Review attachment", "medium", 8, name, "This file type can be abused. Verify the sender and inspect it in a controlled environment.")

    if not findings:
        add("No obvious indicator", "info", 0, "No configured rule matched", "A clean rule-based scan does not prove that a message is safe.")

    score = min(100, sum(f.points for f in findings))
    high_count = sum(1 for f in findings if f.severity == "high")
    if score >= 60 or high_count >= 3:
        classification, action = "MALICIOUS", "Do not interact. Block the sender/domain where appropriate and escalate to the security team."
    elif score >= 20 or high_count >= 1:
        classification, action = "SUSPICIOUS", "Do not click links or open attachments. Warn the user and verify the request through a known, independent channel."
    else:
        classification, action = "SAFE", "No obvious rule-based warning was found. Close only if the context and sender are independently trusted."

    return Analysis(subject, sender, classification, score, [asdict(f) for f in findings], action, [
        "This is a heuristic training tool, not an antivirus engine or a definitive verdict.",
        "A low score does not guarantee safety. Business context, authentication results, and full headers require human review.",
        "The tool does not visit URLs, download files, or execute attachments."
    ])

def analyze_file(path: str) -> Analysis:
    p = Path(path)
    if p.suffix.lower() == ".eml":
        data = extract_eml(p)
    else:
        data = {"subject": p.name, "sender": "", "body": p.read_text(encoding="utf-8", errors="replace")}
    return analyze_message(data)

def save_json(result: Analysis, output: str) -> None:
    Path(output).write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
