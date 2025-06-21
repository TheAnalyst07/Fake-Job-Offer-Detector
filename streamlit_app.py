import streamlit as st
from utils import (
    detect_spam_words,
    detect_suspicious_domain,
    detect_shortened_urls,
    grammar_and_spelling_check,
    check_domain_age,
    extract_entities,
    detect_salary_outlier,
    detect_suspicious_attachments
)

st.set_page_config(page_title="Fake Job Offer Email Detector", page_icon="🕵️")
st.title("🕵️ Fake Job Offer Email Detector")

st.markdown("#### Enter the email details below to detect if the job offer is genuine or fake.")

# User Inputs
sender_email = st.text_input("Enter sender's email:")
email_text = st.text_area("Paste the complete email content here:")

if st.button("Analyze"):
    score = 0
    st.subheader("🔍 **Detailed Analysis:**")

    # 1. Spam Words Detection
    spam_words = detect_spam_words(email_text)
    if spam_words:
        st.warning(f"⚠️ Suspicious keywords found: {spam_words}")
        score += 2
    else:
        st.success("✅ No suspicious keywords detected.")

    # 2. Domain Extension Check
    domain = detect_suspicious_domain(sender_email)
    if domain:
        st.warning(f"⚠️ Suspicious domain extension: .{domain}")
        score += 2
    else:
        st.success("✅ Domain extension looks normal.")

    # 3. Shortened URLs Detection
    urls = detect_shortened_urls(email_text)
    if urls:
        st.warning(f"⚠️ Shortened URLs found: {urls}")
        score += 1
    else:
        st.success("✅ No shortened URLs detected.")

    # 4. WHOIS Domain Age Check
    domain_age = check_domain_age(sender_email)
    if domain_age:
        st.info(f"ℹ️ Domain creation date: {domain_age}")
    else:
        st.warning("⚠️ Could not verify domain age.")
        score += 1

    # 5. Named Entity Recognition (NER)
    entities = extract_entities(email_text)
    st.info(f"ℹ️ Organizations/Entities mentioned: {entities}")

    # 6. Salary/Amount Outlier Detection
    outliers = detect_salary_outlier(email_text)
    if outliers:
        st.warning(f"⚠️ Unrealistic salary/amounts detected: {outliers}")
        score += 1

    # 7. Suspicious Attachment Detection
    attachments = detect_suspicious_attachments(email_text)
    if attachments:
        st.warning(f"⚠️ Suspicious attachment types mentioned: {attachments}")
        score += 1

    # 8. Spelling & Grammar Check
    st.subheader("✍️ **Spelling/Grammar Suggestions:**")
    corrected_text = grammar_and_spelling_check(email_text)
    st.text_area("Corrected Text:", corrected_text, height=200)

    # ✅ Final Verdict
    st.subheader("🔍 **Final Verdict:**")
    if score >= 6:
        st.error("❌ Verdict: HIGHLY SUSPICIOUS or FAKE")
    elif score >= 3:
        st.warning("⚠️ Verdict: Possibly Suspicious — please verify further.")
    else:
        st.success("✅ Verdict: Looks Safe — no major issues found.")

    st.markdown("---")
    st.caption("Note: This is an AI-powered prediction. Always cross-check important emails manually.")
