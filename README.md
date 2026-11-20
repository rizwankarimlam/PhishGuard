# PhishGuard: Phishing Triage Toolkit

**Project:** Cyber Security Project 3 – Phishing Awareness Analysis  
**Type:** Defensive cybersecurity / Python CLI  
**Runtime:** Python 3.10+  
**Dependencies:** Python standard library only

## 1. Objective

PhishGuard helps a user or junior analyst review suspicious email and message samples. It checks message text, sender-related headers, URLs, social-engineering language, and attachment names. It then produces a transparent risk score, lists the matched indicators, and recommends a response.

The project implements the DecodeLabs brief:
- Identify suspicious links and keywords.
- List red flags found in phishing messages.
- Explain why a message may be unsafe.
- Provide a non-expert triage checklist and decision tree.
- End every triage with an actionable outcome: Safe → Close; Suspicious → Warn User; Malicious → Block & Escalate.

## 2. Features

- Analyze `.eml` email files and `.txt` message samples.
- Interactive manual message analysis.
- Inspect From, Reply-To, and Return-Path domain mismatches.
- Extract URLs without opening them.
- Flag URL shorteners, Punycode, lookalike brand domains, and unusual URL structures.
- Detect urgency, authority, fear/reward, and requests for sensitive information.
- Flag risky attachment extensions by filename only.
- Generate console and JSON reports.
- Includes sample messages and unit tests.

## 3. Project structure

```text
PhishGuard/
├── main.py
├── requirements.txt
├── README.md
├── phishguard/
│   ├── __init__.py
│   ├── analyzer.py
│   └── cli.py
├── samples/
│   ├── suspicious_email.txt
│   ├── legitimate_email.txt
│   └── suspicious_email.eml
├── reports/
└── tests/
    └── test_analyzer.py
```

## 4. Installation

1. Install Python 3.10 or later.
2. Extract the project ZIP.
3. Open a terminal in the `PhishGuard` directory.
4. (Optional) Create and activate a virtual environment.

Windows:
```powershell
py -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

No external packages are required.

## 5. Run the project

Analyze a text sample:
```bash
python main.py samples/suspicious_email.txt
```

Analyze an email file:
```bash
python main.py samples/suspicious_email.eml
```

Interactive mode:
```bash
python main.py --interactive
```

Save a JSON report:
```bash
python main.py samples/suspicious_email.eml --json reports/analysis.json
```

Windows users can also use `py main.py ...` instead of `python`.

## 6. How the risk score works

The tool adds points for configured indicators. Examples:
- From/Reply-To domain mismatch: 18
- Lookalike domain: 20
- Punycode domain: 15
- URL shortener: 10
- Sensitive information request: 6–8
- Risky executable/script attachment: 20
- Urgency and authority phrases: 3–8

Classification:
- **SAFE:** score below 20 and no high-severity finding.
- **SUSPICIOUS:** score 20–59, or at least one high-severity finding.
- **MALICIOUS:** score 60 or higher, or at least three high-severity findings.

This scoring is an educational heuristic. It is not a calibrated probability of compromise and must not be used as the sole basis for blocking a real sender.

## 7. Triage checklist

Before deciding, check:

1. Is the sender's full email address consistent with the claimed organization?
2. Do From, Reply-To, and Return-Path domains make sense?
3. Does the message create artificial urgency or secrecy?
4. Does it request a password, OTP, recovery code, or payment information?
5. Does the visible link lead to the expected official domain?
6. Is the domain misspelled, lookalike, shortened, or unusually nested?
7. Is the attachment unexpected or executable?
8. Does the request fit the normal business process?
9. Can the request be verified using a known phone number or trusted internal channel?
10. Has the message been reported to the appropriate security contact?

## 8. Decision tree

```text
Incoming suspicious message
          |
          v
Inspect sender, headers, URLs, content and attachments
          |
          v
Are strong malicious indicators present?
      /             \
    Yes              No
     |                |
     v                v
MALICIOUS       Are unresolved red flags present?
     |             /          \
     v           Yes           No
Block &          |              |
Escalate         v              v
              SUSPICIOUS       SAFE*
                 |               |
                 v               v
             Warn user       Close only after
             & verify        contextual verification
```

`SAFE` means no configured indicator was detected. It does not mean a message is guaranteed safe.

## 9. Safe operating procedure

- Use only synthetic samples or messages you are authorized to inspect.
- Do not click extracted URLs.
- Do not execute or open suspicious attachments.
- Do not paste real passwords, OTPs, recovery codes, or confidential data into the tool.
- Verify financial or executive requests through a previously known, independent channel.
- Follow your organization's incident-reporting process.

## 10. Limitations and future improvements

Current version uses transparent keyword and pattern rules. It does not:
- Validate SPF, DKIM, or DMARC DNS results.
- Query threat-intelligence feeds or reputation APIs.
- Resolve shortened URLs.
- Render HTML email or inspect attachment contents.
- Detect every homograph or newly registered malicious domain.
- Use machine learning.

Possible future improvements include authenticated header analysis, a local web dashboard, configurable allow/deny lists, threat-intelligence integrations, and analyst feedback.

## 11. Test

Run:
```bash
python -m unittest discover -s tests -v
```

## 12. Project conclusion

PhishGuard turns phishing awareness concepts into a repeatable triage workflow. It teaches users to pause, verify, and report, while giving analysts a structured way to document evidence and choose an appropriate response.
