
import streamlit as st
import json
from datetime import datetime
from phishguard.analyzer import analyze_email

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #07111f, #0b1d33);
    color: #ffffff;
}
.block-container {
    max-width: 1150px;
    padding-top: 2rem;
}
.hero {
    background: #102641;
    border: 1px solid #28517e;
    border-radius: 18px;
    padding: 30px;
    margin-bottom: 25px;
}
.hero h1 {
    color: #ffffff;
    font-size: 42px;
}
.hero p {
    color: #b8cce5;
}
.metric {
    background: #102641;
    border: 1px solid #28517e;
    border-radius: 14px;
    padding: 20px;
    text-align: center;
}
.metric h2 {
    color: #55aaff;
}
.stTextArea textarea {
    background: #0a1b30 !important;
    color: white !important;
}
.stButton button, .stDownloadButton button {
    background: #1769c2;
    color: white;
    border-radius: 9px;
    border: none;
}
.stButton button:hover, .stDownloadButton button:hover {
    background: #2489ed;
    color: white;
}
[data-testid="stFileUploader"] {
    background: #102641;
    border-radius: 12px;
    padding: 15px;
}
div[data-testid="stExpander"] {
    background: #102641;
    border: 1px solid #28517e;
}
section[data-testid="stSidebar"] {
    background: #09182b;
}
footer {
    visibility: hidden;
}
a {
    color: #70baff !important;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <h1>🛡️ PhishGuard</h1>
    <p>Email Phishing Detection & Threat Analysis Platform</p>
    <p>Analyze suspicious emails and identify potential phishing indicators.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("🛡️ PhishGuard")
    st.caption("Email Security Analyzer")
    st.divider()
    st.subheader("How to use")
    st.write("1. Upload an email file.")
    st.write("2. Click Analyze Email.")
    st.write("3. Review the results.")
    st.divider()
    st.warning(
        "This tool uses heuristic checks. "
        "It cannot guarantee that an email is safe."
    )

tab1, tab2 = st.tabs(["📎 Upload Email", "✍️ Paste Email"])

email_text = ""
source_name = "pasted_email.txt"

with tab1:
    uploaded = st.file_uploader(
        "Upload your email",
        type=["eml", "txt"]
    )

    if uploaded:
        source_name = uploaded.name
        email_text = uploaded.getvalue().decode(
            "utf-8", errors="replace"
        )
        st.success(f"Loaded: {uploaded.name}")

with tab2:
    pasted = st.text_area(
        "Paste your email content here",
        height=250,
        placeholder="From: example@gmail.com\nSubject: Verify your account..."
    )

    if pasted.strip():
        email_text = pasted.strip()
        source_name = "pasted_email.txt"

if st.button("🔍 Analyze Email", use_container_width=True):
    if not email_text.strip():
        st.warning("Please upload or paste an email first.")
    else:
        st.session_state.result = analyze_email(email_text)
        st.session_state.source = source_name

if "result" in st.session_state:
    result = st.session_state.result

    st.divider()
    st.header("📊 Analysis Results")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown(
            f'<div class="metric"><h2>{result["risk_score"]}/100</h2>'
            '<p>Risk Score</p></div>',
            unsafe_allow_html=True
        )

    with c2:
        st.markdown(
            f'<div class="metric"><h2>{result["classification"]}</h2>'
            '<p>Classification</p></div>',
            unsafe_allow_html=True
        )

    with c3:
        st.markdown(
            f'<div class="metric"><h2>{len(result["findings"])}</h2>'
            '<p>Indicators Found</p></div>',
            unsafe_allow_html=True
        )

    st.subheader("Analysis Summary")
    st.info(result["summary"])

    left, right = st.columns(2)

    with left:
        st.subheader("🔎 Security Findings")

        if result["findings"]:
            for finding in result["findings"]:
                with st.expander(finding["title"]):
                    st.write(finding["detail"])
                    st.caption(
                        f"Risk points: {finding['points']}"
                    )
        else:
            st.success("No obvious indicators detected.")

    with right:
        st.subheader("✅ Recommended Actions")

        for action in result["recommendations"]:
            st.write("• " + action)

        st.subheader("📧 Email Information")

        for key, value in result["email_details"].items():
            st.write(f"**{key}:** {value or 'Not available'}")

    report = {
        "tool": "PhishGuard",
        "developer": "Rizwan Karim Lam",
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "source": st.session_state.get("source", "email"),
        **result
    }

    st.divider()
    st.subheader("📥 Download Reports")

    json_data = json.dumps(report, indent=4)

    st.download_button(
        "Download JSON Report",
        json_data,
        file_name="phishguard_report.json",
        mime="application/json"
    )

    try:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 18)
        pdf.cell(0, 12, "PhishGuard Analysis Report", ln=True)

        pdf.set_font("Arial", size=11)
        pdf.cell(0, 9, f"Risk Score: {result['risk_score']}/100", ln=True)
        pdf.cell(0, 9, f"Classification: {result['classification']}", ln=True)
        pdf.multi_cell(0, 8, result["summary"])

        pdf.ln(5)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Security Findings", ln=True)

        pdf.set_font("Arial", size=10)
        for item in result["findings"]:
            pdf.multi_cell(
                0, 7,
                f"{item['title']}: {item['detail']}"
            )

        pdf.ln(4)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Recommendations", ln=True)

        pdf.set_font("Arial", size=10)
        for action in result["recommendations"]:
            pdf.multi_cell(0, 7, action)

        pdf_bytes = bytes(pdf.output())

        st.download_button(
            "Download PDF Report",
            pdf_bytes,
            file_name="phishguard_report.pdf",
            mime="application/pdf"
        )

    except Exception as error:
        st.warning("PDF report could not be generated.")

st.divider()

st.markdown("""
<div style="text-align:center; padding:20px;">
    <h3 style="color:#ffffff;">PhishGuard</h3>
    <p>Developed by <b>Rizwan Karim Lam</b></p>
    <a href="https://www.linkedin.com/in/rizwan-karim-lam/"
       target="_blank">
       Connect with me on LinkedIn ↗
    </a>
    <p style="color:#9eb4ce; font-size:12px;">
       Educational Cybersecurity Project
    </p>
</div>
""", unsafe_allow_html=True)
