import argparse
from dataclasses import asdict
from pathlib import Path
from .analyzer import analyze_file, analyze_message, save_json

def show(result):
    print("\n" + "=" * 62)
    print(" PHISHGUARD | PHISHING TRIAGE REPORT")
    print("=" * 62)
    print(f"Subject       : {result.subject or '(not provided)'}")
    print(f"Sender        : {result.sender or '(not provided)'}")
    print(f"Classification: {result.classification}")
    print(f"Risk score    : {result.risk_score}/100")
    print("\nFINDINGS")
    for i, item in enumerate(result.findings, 1):
        print(f"{i}. [{item['severity'].upper()}] {item['category']} (+{item['points']})")
        print(f"   Evidence: {item['evidence']}")
        print(f"   Why it matters: {item['explanation']}")
    print("\nRECOMMENDED ACTION")
    print(result.recommended_action)
    print("\nLIMITATIONS")
    for note in result.limitations:
        print(f"- {note}")
    print("=" * 62)

def main():
    parser = argparse.ArgumentParser(description="Analyze a message for phishing indicators.")
    parser.add_argument("file", nargs="?", help="Path to a .eml or .txt sample")
    parser.add_argument("--json", dest="json_path", help="Save machine-readable report to this path")
    parser.add_argument("--interactive", action="store_true", help="Enter message details manually")
    args = parser.parse_args()

    if args.interactive:
        print("Paste a message for local analysis. Do not paste real passwords or OTPs.")
        subject = input("Subject: ")
        sender = input("From address: ")
        reply_to = input("Reply-To (optional): ")
        body = input("Message body: ")
        result = analyze_message({"subject": subject, "sender": sender, "reply_to": reply_to, "body": body})
    elif args.file:
        result = analyze_file(args.file)
    else:
        parser.error("Provide a file path or use --interactive")

    show(result)
    if args.json_path:
        save_json(result, args.json_path)
        print(f"\nJSON report saved to: {args.json_path}")

if __name__ == "__main__":
    main()
