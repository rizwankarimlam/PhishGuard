# PhishGuard Web App

A Streamlit web interface for the existing PhishGuard phishing-triage engine.

## Run locally

1. Install Python 3.10 or newer.
2. Open a terminal inside this `PhishGuard` folder.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Start the website:

   ```bash
   streamlit run app.py
   ```

5. Open the local address shown in the terminal (usually `http://localhost:8501`).

## Deploy online with Streamlit Community Cloud

1. Create a GitHub account if you do not already have one.
2. Create a new **public** GitHub repository named `PhishGuard`.
3. Upload the contents of this folder to the repository. Make sure `app.py`, `requirements.txt`, and the `phishguard` folder are at the repository root.
4. Open https://share.streamlit.io/ and sign in with GitHub.
5. Select **Create app**, choose your repository and branch, and set **Main file path** to `app.py`.
6. Click **Deploy**. Streamlit will install `requirements.txt` and publish a shareable website URL.

## Features

- Upload `.eml` and `.txt` files.
- Paste email subject, sender, Reply-To and body.
- Display SAFE / SUSPICIOUS / MALICIOUS classification and risk score.
- Explain matched indicators and recommended action.
- Download JSON and PDF analysis reports.

## Safety and limitations

- The analyzer is heuristic and intended for learning and first-pass triage, not as a definitive verdict.
- A SAFE result does not prove that a message is legitimate.
- The app does not visit links, fetch remote content, or execute attachments.
- Do not upload confidential emails, passwords, OTPs, private attachments, or sensitive personal information to a public deployment.
- Anyone with access to the public app may be able to submit content for analysis. Use synthetic or sanitized samples for demonstrations.
