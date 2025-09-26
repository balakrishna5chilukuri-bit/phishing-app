import streamlit as st
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from datetime import datetime
import re
from urllib.parse import urlparse

# -------------------------
# Mock data (adapted from your Tkinter app)
# -------------------------
PHISHING_DATA = {
    "trends": [
        {"month": "Jan", "phishingEmails": 145, "spoofingAttempts": 89, "maliciousUrls": 112},
        {"month": "Feb", "phishingEmails": 159, "spoofingAttempts": 97, "maliciousUrls": 128},
        {"month": "Mar", "phishingEmails": 170, "spoofingAttempts": 105, "maliciousUrls": 143},
        {"month": "Apr", "phishingEmails": 201, "spoofingAttempts": 118, "maliciousUrls": 167},
        {"month": "May", "phishingEmails": 238, "spoofingAttempts": 127, "maliciousUrls": 195},
        {"month": "Jun", "phishingEmails": 250, "spoofingAttempts": 140, "maliciousUrls": 210},
        {"month": "Jul", "phishingEmails": 265, "spoofingAttempts": 155, "maliciousUrls": 225},
        {"month": "Aug", "phishingEmails": 240, "spoofingAttempts": 130, "maliciousUrls": 200},
        {"month": "Sep", "phishingEmails": 280, "spoofingAttempts": 160, "maliciousUrls": 240},
        {"month": "Oct", "phishingEmails": 310, "spoofingAttempts": 180, "maliciousUrls": 270},
        {"month": "Nov", "phishingEmails": 350, "spoofingAttempts": 210, "maliciousUrls": 300},
        {"month": "Dec", "phishingEmails": 330, "spoofingAttempts": 190, "maliciousUrls": 280}
    ],
    "distribution": [
        {"name": "Financial", "value": 30},
        {"name": "Cloud Services", "value": 20},
        {"name": "Email Service", "value": 15},
        {"name": "E-commerce", "value": 12},
        {"name": "Government", "value": 10},
        {"name": "Healthcare", "value": 8},
        {"name": "Social Media", "value": 5}
    ],
    "stats": {
        "totalAttacks": "28,741",
        "successRate": "19%",
        "mostTargeted": "Financial",
        "commonVector": "Email Links"
    }
}

# -------------------------
# Utility: scanner logic (heuristic)
# -------------------------
def perform_url_scan(url: str):
    """Simplified heuristic-based scanner returning findings, score and risk level."""
    score = 0
    findings = []

    if not url:
        return None

    # ensure scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname.lower() if parsed.hostname else ""
    except Exception:
        domain = ""

    # IP address in URL
    if re.search(r"\b\d+\.\d+\.\d+\.\d+\b", url):
        score += 25
        findings.append({"description": "IP address used in URL", "details": "IP addresses may hide malicious domains."})

    # '@' in URL (credential inclusion trick)
    if "@" in url:
        score += 20
        findings.append({"description": "At symbol '@' in URL", "details": "Can be used to obscure destination domain."})

    # brand impersonation
    brands = ["paypal", "apple", "microsoft", "google", "amazon", "facebook", "chase", "netflix", "coinbase"]
    for b in brands:
        if b in domain and not domain.endswith(f"{b}.com"):
            score += 30
            findings.append({"description": "Brand impersonation detected", "details": f"Possible {b} impersonation"})
            break

    # excessive subdomains
    parts = domain.split('.') if domain else []
    if len(parts) > 4:
        score += 10
        findings.append({"description": "Excessive subdomains", "details": "Multiple subdomains may obscure the real domain."})

    # suspicious tld
    suspicious_tlds = ['xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'info', 'club', 'top']
    if parts and parts[-1] in suspicious_tlds:
        score += 15
        findings.append({"description": "Suspicious TLD", "details": f"The TLD .{parts[-1]} is often used in phishing."})

    # clamp
    score = min(score, 100)

    if score >= 75:
        risk = "High"
    elif score >= 40:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "id": int(datetime.utcnow().timestamp()),
        "url": url,
        "risk": risk,
        "score": score,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings": findings
    }

# -------------------------
# Streamlit App
# -------------------------
st.set_page_config(page_title="Phishing Detection System", layout="wide")
st.title("Phishing Detection System")

if "history" not in st.session_state:
    # populate with some example results (mirrors your sample_results)
    st.session_state.history = [
        {"id": 1, "url": "https://paypal-secure.verifynow-id.com/login", "risk": "High", "score": 87, "timestamp": "2025-09-25 10:23:15",
         "findings": [{"description": "Brand impersonation detected", "details": "PayPal impersonation"}, {"description": "Domain age", "details": "3 days (simulated)"}]},
        {"id": 2, "url": "http://chase-online-security.info/update/login.html", "risk": "High", "score": 92, "timestamp": "2025-09-25 09:45:10",
         "findings": [{"description": "Brand impersonation", "details": "Possible Chase impersonation"}, {"description": "Suspicious TLD", "details": ".info often used in attacks"}]},
        {"id": 10, "url": "https://google.com", "risk": "Low", "score": 2, "timestamp": "2025-09-22 10:18:00", "findings": []},
    ]

# Tabs: Dashboard | Scanner | History
tabs = st.tabs(["Dashboard", "URL Scanner", "History"])

# ---------- Dashboard ----------
with tabs[0]:
    st.subheader("Overview")
    stats = PHISHING_DATA["stats"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Attacks", stats["totalAttacks"])
    c2.metric("Success Rate", stats["successRate"])
    c3.metric("Most Targeted", stats["mostTargeted"])
    c4.metric("Common Vector", stats["commonVector"])

    # Trends chart - grouped bars
    st.markdown("### Attack Trends (12 months)")
    trends = PHISHING_DATA["trends"]
    months = [t["month"] for t in trends]
    phishing_emails = [t["phishingEmails"] for t in trends]
    spoofing = [t["spoofingAttempts"] for t in trends]
    malicious = [t["maliciousUrls"] for t in trends]

    fig, ax = plt.subplots(figsize=(10, 4))
    x = np.arange(len(months))
    w = 0.25
    ax.bar(x - w, phishing_emails, width=w, label="Phishing Emails")
    ax.bar(x, spoofing, width=w, label="Spoofing Attempts")
    ax.bar(x + w, malicious, width=w, label="Malicious URLs")
    ax.set_xticks(x)
    ax.set_xticklabels(months)
    ax.set_ylabel("Count")
    ax.legend()
    ax.set_title("Monthly Phishing Metrics")
    st.pyplot(fig)

    # Distribution pie
    st.markdown("### Attack Target Distribution")
    dist = PHISHING_DATA["distribution"]
    labels = [d["name"] for d in dist]
    values = [d["value"] for d in dist]
    fig2, ax2 = plt.subplots(figsize=(6, 4))
    ax2.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    ax2.axis("equal")
    st.pyplot(fig2)

# ---------- Scanner ----------
with tabs[1]:
    st.subheader("URL Scanner")
    col_input, col_actions = st.columns([3,1])
    with col_input:
        url_input = st.text_input("Enter URL to scan", placeholder="e.g. paypal-login.example.com")
    with col_actions:
        scan_btn = st.button("Scan URL")

    if scan_btn:
        if not url_input:
            st.warning("Please enter a URL to scan.")
        else:
            result = perform_url_scan(url_input.strip())
            # Insert at start of history
            st.session_state.history.insert(0, result)
            st.success(f"Scan complete — Risk: {result['risk']} ({result['score']}%)")
            st.write("**Scanned URL:**", result["url"])
            st.write("**Timestamp:**", result["timestamp"])
            if result["findings"]:
                st.markdown("**Findings**")
                for f in result["findings"]:
                    st.markdown(f"- **{f['description']}** — {f['details']}")
            else:
                st.info("No suspicious indicators detected.")

# ---------- History ----------
with tabs[2]:
    st.subheader("Scan History")
    history = st.session_state.history
    if history:
        # show table with selectable rows
        df = pd.DataFrame([{"URL": h["url"], "Risk": h["risk"], "Score": h["score"], "Timestamp": h["timestamp"], "id": h["id"]} for h in history])
        st.dataframe(df.drop(columns=["id"]), use_container_width=True)

        # allow user to pick an entry to view details
        ids = [h["id"] for h in history]
        labels = [f"{h['timestamp']}  |  {h['url'][:80]}" for h in history]
        selected_idx = st.selectbox("Select a scan to view details", options=range(len(history)), format_func=lambda i: labels[i])
        item = history[selected_idx]
        st.markdown("### Selected Scan Details")
        st.write("**URL:**", item["url"])
        st.write("**Risk:**", item["risk"], f"({item['score']}%)")
        st.write("**Timestamp:**", item["timestamp"])
        if item.get("findings"):
            st.markdown("**Findings**")
            for f in item["findings"]:
                st.markdown(f"- **{f['description']}** — {f['details']}")
        else:
            st.info("No findings for this scan.")

        # allow download of history as CSV
        pd_hist = pd.DataFrame(history)
        csv = pd_hist.to_csv(index=False)
        st.download_button("Download history CSV", csv, file_name="scan_history.csv", mime="text/csv")
    else:
        st.info("No scans yet. Use the URL Scanner tab to run a scan.")
