from __future__ import annotations

import json
import tempfile
from dataclasses import asdict
from io import BytesIO
from pathlib import Path

import streamlit as st
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

from phishguard.analyzer import analyze_file, analyze_message

st.set_page_config(page_title="PhishGuard | Email Security Analyzer", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
  .stApp { background: #f4f7fc; }
  [data-testid="stHeader"] { background: rgba(244,247,252,.9); }
  .hero { background: linear-gradient(120deg,#101d3b,#174b86); padding: 28px 32px; border-radius: 18px; color: white; margin-bottom: 22px; }
  .hero h1 { color: white; margin: 0; font-size: 2.15rem; }
  .hero p { color: #dce9ff; margin: 8px 0 0 0; }
  .metric-card { background: white; border: 1px solid #e3eaf5; border-radius: 14px; padding: 18px; min-height: 112px; }
  .metric-label { color: #60718b; font-size: .86rem; }
  .metric-value { color: #14294b; font-size: 1.65rem; font-weight: 750; margin-top: 7px; }
  .small-note { color: #61718a; font-size: .86rem; }
  div.stButton > button[kind="primary"] { background: #1759a6; border: 0; }
</style>
<div class="hero">
  <h1>🛡️ PhishGuard</h1>
  <p>Phishing Awareness & Email Triage Toolkit · Analyze suspicious messages safely</p>
</div>
""", unsafe_allow_html=True)


def analyze_uploaded(uploaded_file):
    raw = uploaded_file.getvalue()
    suffix = Path(uploaded_file.name).suffix.lower()
    if suffix == ".eml":
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
            tmp.write(raw)
            temp_path = tmp.name
        try:
            return analyze_file(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    if suffix == ".txt":
        text = raw.decode("utf-8", errors="replace")
        return analyze_message({"subject": uploaded_file.name, "sender": "", "body": text})
    raise ValueError("Please upload an .eml or .txt file.")


def make_pdf(result):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="PGTitle", parent=styles["Title"], textColor=colors.HexColor("#163b6c"), alignment=0, spaceAfter=8))
    styles.add(ParagraphStyle(name="PGSmall", parent=styles["BodyText"], fontSize=8, leading=11, textColor=colors.HexColor("#42536b")))
    story = [Paragraph("PhishGuard Analysis Report", styles["PGTitle"]),
             Paragraph(f"<b>Subject:</b> {result.subject or '(not provided)'}", styles["BodyText"]),
             Paragraph(f"<b>Sender:</b> {result.sender or '(not provided)'}", styles["BodyText"]),
             Paragraph(f"<b>Classification:</b> {result.classification} &nbsp;&nbsp; <b>Risk score:</b> {result.risk_score}/100", styles["BodyText"]), Spacer(1, 10)]
    rows = [["Severity", "Finding", "Points", "Evidence", "Explanation"]]
    for f in result.findings:
        rows.append([f["severity"].upper(), f["category"], str(f["points"]), f["evidence"], f["explanation"]])
    table = Table(rows, colWidths=[20*mm, 30*mm, 13*mm, 48*mm, 62*mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#163b6c")), ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 7),
        ("LEADING", (0,0), (-1,-1), 9), ("GRID", (0,0), (-1,-1), .35, colors.HexColor("#d5deea")),
        ("VALIGN", (0,0), (-1,-1), "TOP"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f1f5fa")]),
        ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5),
    ]))
    story += [Paragraph("Findings", styles["Heading2"]), table, Spacer(1, 12),
              Paragraph("Recommended action", styles["Heading2"]), Paragraph(result.recommended_action, styles["BodyText"]),
              Spacer(1, 8), Paragraph("Limitations", styles["Heading2"])]
    story.extend(Paragraph("• " + note, styles["PGSmall"]) for note in result.limitations)
    doc.build(story)
    return buffer.getvalue()


def show_result(result):
    st.divider()
    st.subheader("Analysis result")
    status_colors = {"SAFE": "🟢", "SUSPICIOUS": "🟠", "MALICIOUS": "🔴"}
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Classification</div><div class="metric-value">{status_colors.get(result.classification, "⚪")} {result.classification}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Risk score</div><div class="metric-value">{result.risk_score}/100</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Indicators found</div><div class="metric-value">{len([f for f in result.findings if f["points"] > 0])}</div></div>', unsafe_allow_html=True)
    st.progress(result.risk_score / 100)
    st.markdown(f"**Subject:** {result.subject or '(not provided)'}  \n**Sender:** {result.sender or '(not provided)'}")
    st.markdown("#### Red flags and observations")
    for f in result.findings:
        icon = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}.get(f["severity"], "⚪")
        with st.expander(f"{icon} {f['category']} · {f['severity'].upper()} · +{f['points']} points"):
            st.write("**Evidence:**", f["evidence"])
            st.write("**Why it matters:**", f["explanation"])
    st.info("**Recommended action:** " + result.recommended_action)
    with st.expander("Important limitations"):
        for note in result.limitations:
            st.write("• " + note)
    report = asdict(result)
    safe_name = "phishguard_report"
    d1, d2 = st.columns(2)
    with d1:
        st.download_button("⬇️ Download JSON report", json.dumps(report, indent=2), file_name=f"{safe_name}.json", mime="application/json", use_container_width=True)
    with d2:
        st.download_button("⬇️ Download PDF report", make_pdf(result), file_name=f"{safe_name}.pdf", mime="application/pdf", use_container_width=True)

st.markdown("### Choose how to provide the email")
upload_tab, paste_tab = st.tabs(["📎 Upload email file", "✍️ Paste email text"])
result = None
with upload_tab:
    uploaded = st.file_uploader("Upload an email file", type=["eml", "txt"], help="Supported formats: .eml and .txt")
    if uploaded is not None:
        st.caption(f"Selected file: {uploaded.name} · {len(uploaded.getvalue()):,} bytes")
        if st.button("Analyze uploaded email", type="primary", use_container_width=True):
            try:
                with st.spinner("Analyzing email indicators..."):
                    result = analyze_uploaded(uploaded)
                st.session_state["last_result"] = result
            except Exception as exc:
                st.error(f"Could not analyze this file: {exc}")
with paste_tab:
    subject = st.text_input("Email subject", placeholder="Example: Urgent account verification")
    sender = st.text_input("From address (optional)", placeholder="Example: support@example.com")
    reply_to = st.text_input("Reply-To address (optional)", placeholder="Example: help@example.com")
    body = st.text_area("Email body", height=220, placeholder="Paste the email content here...")
    if st.button("Analyze pasted email", type="primary", use_container_width=True):
        if not body.strip() and not subject.strip():
            st.warning("Please enter an email subject or body first.")
        else:
            with st.spinner("Analyzing email indicators..."):
                result = analyze_message({"subject": subject, "sender": sender, "reply_to": reply_to, "body": body})
            st.session_state["last_result"] = result

if "last_result" in st.session_state:
    show_result(st.session_state["last_result"])

st.divider()
st.markdown("<div class='small-note'>PhishGuard is an educational, rule-based triage assistant. It does not open URLs, download attachments, or prove that an email is safe. Verify important requests through a trusted channel.</div>", unsafe_allow_html=True)
