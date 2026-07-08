"""
AI-Powered AWS Threat Detection System -- Portfolio Demo Dashboard
--------------------------------------------------------------------
A Streamlit dashboard that simulates the CloudTrail -> GuardDuty ->
EventBridge -> Lambda -> SNS pipeline using mock GuardDuty findings.

This demo intentionally makes NO live AWS calls (no credentials needed,
free to host forever on Streamlit Community Cloud). It reuses the exact
same severity-scoring and remediation-knowledge-base logic that runs in
the real `lambda/threat_processor.py` in production, so the alerts you
see here are formatted identically to what a subscriber would receive
by Email/SMS in the deployed system.

Run locally:
    pip install -r streamlit_app/requirements.txt
    streamlit run streamlit_app/app.py

Deploy for free:
    https://share.streamlit.io -> New app -> point at this repo,
    main file path: streamlit_app/app.py
"""

import json
import os
import random
import sys
import uuid
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# Reuse the REAL detection logic from the Lambda function, so this demo
# stays perfectly in sync with what actually runs in production.
# ---------------------------------------------------------------------------
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:000000000000:demo-topic")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
from threat_processor import (  # noqa: E402
    REMEDIATION_KB,
    get_remediation,
    severity_label,
)

st.set_page_config(
    page_title="AWS Threat Detection - Live Demo",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Mock GuardDuty findings catalog (realistic finding types/titles/descriptions)
# ---------------------------------------------------------------------------
SAMPLE_FINDINGS = [
    {
        "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "title": "Bitcoin mining activity detected on EC2 instance",
        "description": "EC2 instance i-0a1b2c3d4e5f is querying a domain "
                        "name associated with cryptocurrency mining pools.",
        "severity": 8.5,
        "resource_type": "Instance",
        "resource_id": "i-0a1b2c3d4e5f",
    },
    {
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "title": "IAM credentials exfiltrated to an external IP address",
        "description": "Credentials for IAM user 'svc-deploy' were used "
                        "from an IP address outside your AWS account and "
                        "are believed to be compromised.",
        "severity": 8.0,
        "resource_type": "AccessKey",
        "resource_id": "AKIA-svc-deploy",
    },
    {
        "type": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "title": "Console login from an unusual, unauthorized location",
        "description": "An IAM user console login occurred from an IP "
                        "address and location not previously seen for "
                        "this account.",
        "severity": 5.5,
        "resource_type": "IAMUser",
        "resource_id": "user-jsmith",
    },
    {
        "type": "Backdoor:EC2/C&CActivity.B!DNS",
        "title": "EC2 instance communicating with a command-and-control server",
        "description": "EC2 instance i-0f9e8d7c6b5a is querying a domain "
                        "associated with a known command-and-control "
                        "server, indicating possible backdoor compromise.",
        "severity": 8.9,
        "resource_type": "Instance",
        "resource_id": "i-0f9e8d7c6b5a",
    },
    {
        "type": "Trojan:EC2/DNSDataExfiltration",
        "title": "Possible data exfiltration via DNS detected",
        "description": "EC2 instance i-0c1d2e3f4a5b is exhibiting DNS "
                        "query patterns consistent with data exfiltration.",
        "severity": 8.0,
        "resource_type": "Instance",
        "resource_id": "i-0c1d2e3f4a5b",
    },
    {
        "type": "Recon:EC2/PortProbeUnprotectedPort",
        "title": "Unprotected port being probed by a known scanner",
        "description": "EC2 instance i-0d4c3b2a1f0e has an unprotected "
                        "port being probed by a host known for scanning "
                        "activity.",
        "severity": 2.0,
        "resource_type": "Instance",
        "resource_id": "i-0d4c3b2a1f0e",
    },
    {
        "type": "Policy:IAMUser/RootCredentialUsage",
        "title": "Root account credentials used",
        "description": "The AWS account root user credentials were used "
                        "to make an API call, violating least-privilege "
                        "best practice.",
        "severity": 5.0,
        "resource_type": "IAMUser",
        "resource_id": "root",
    },
    {
        "type": "Exfiltration:S3/ObjectRead.Unusual",
        "title": "Unusual volume of S3 object reads detected",
        "description": "An unusually high volume of GetObject calls was "
                        "made against S3 bucket 'company-financial-data' "
                        "from an unfamiliar principal.",
        "severity": 7.0,
        "resource_type": "S3Bucket",
        "resource_id": "company-financial-data",
    },
]

SEVERITY_COLORS = {
    "CRITICAL": "#c0152f",
    "HIGH": "#e8491d",
    "MEDIUM": "#f5a623",
    "LOW": "#2f9e44",
}


def build_mock_event(finding_def: dict) -> dict:
    """Build a synthetic EventBridge/GuardDuty event, same shape the real Lambda receives."""
    return {
        "id": str(uuid.uuid4()),
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "region": "us-east-1",
        "time": datetime.now(timezone.utc).isoformat(),
        "detail": {
            "id": str(uuid.uuid4()),
            "type": finding_def["type"],
            "title": finding_def["title"],
            "description": finding_def["description"],
            "severity": finding_def["severity"],
            "resource": {
                "resourceType": finding_def["resource_type"],
                "instanceDetails": {"instanceId": finding_def["resource_id"]},
            },
        },
    }


def process_finding(event: dict) -> dict:
    """
    Mirrors what lambda/threat_processor.py does internally, minus the
    actual SNS publish call (no live AWS calls in this demo).
    """
    detail = event["detail"]
    remediation = get_remediation(detail["type"])
    level = severity_label(detail["severity"])
    return {
        "timestamp": event["time"],
        "finding_type": detail["type"],
        "title": detail["title"],
        "description": detail["description"],
        "severity_score": detail["severity"],
        "severity_label": level,
        "resource": f"{detail['resource']['resourceType']} "
                    f"({detail['resource']['instanceDetails']['instanceId']})",
        "summary": remediation["summary"],
        "steps": remediation["steps"],
    }


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
if "alerts" not in st.session_state:
    st.session_state.alerts = []

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("🛡️ AI-Powered AWS Threat Detection System")
st.caption(
    "Portfolio demo — simulates GuardDuty findings flowing through the "
    "real detection & remediation logic. No live AWS account is connected; "
    "the production system deploys via the CloudFormation template in "
    "`infrastructure/cloudformation/template.yaml`."
)

# ---------------------------------------------------------------------------
# Pipeline visual
# ---------------------------------------------------------------------------
pipeline_cols = st.columns(6)
pipeline_steps = [
    ("☁️", "CloudTrail", "Collects activity logs"),
    ("🛡️", "GuardDuty", "Analyzes logs"),
    ("🔀", "EventBridge", "Listens for findings"),
    ("⚡", "Lambda", "Enriches + generates alert"),
    ("📨", "SNS", "Sends notifications"),
    ("📧📱", "Email / SMS", "Admin gets alerted"),
]
for col, (icon, name, desc) in zip(pipeline_cols, pipeline_steps):
    with col:
        st.markdown(
            f"""<div style="text-align:center; padding:10px; border-radius:10px;
            background-color:rgba(127,127,127,0.08); min-height:110px;">
            <div style="font-size:28px;">{icon}</div>
            <div style="font-weight:600; margin-top:4px;">{name}</div>
            <div style="font-size:12px; opacity:0.75;">{desc}</div>
            </div>""",
            unsafe_allow_html=True,
        )

st.divider()

# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------
st.sidebar.header("⚙️ Simulate a Threat")

finding_labels = [f"{f['type']}  (sev {f['severity']})" for f in SAMPLE_FINDINGS]
choice = st.sidebar.selectbox(
    "Choose a GuardDuty finding type",
    options=range(len(SAMPLE_FINDINGS)),
    format_func=lambda i: finding_labels[i],
)

col_a, col_b = st.sidebar.columns(2)
trigger_selected = col_a.button("🚨 Trigger", use_container_width=True)
trigger_random = col_b.button("🎲 Random", use_container_width=True)

if st.sidebar.button("🧹 Clear alert history", use_container_width=True):
    st.session_state.alerts = []

st.sidebar.divider()
st.sidebar.markdown(
    "**About this demo**\n\n"
    "This dashboard runs the identical `get_remediation()` and "
    "`severity_label()` functions used by the production Lambda "
    "(`lambda/threat_processor.py`) against mock GuardDuty findings, "
    "so the remediation guidance shown here matches production exactly."
)

if trigger_selected or trigger_random:
    finding_def = (
        SAMPLE_FINDINGS[choice] if trigger_selected else random.choice(SAMPLE_FINDINGS)
    )
    event = build_mock_event(finding_def)
    alert = process_finding(event)
    st.session_state.alerts.insert(0, alert)

# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
alerts = st.session_state.alerts
total = len(alerts)
critical = sum(1 for a in alerts if a["severity_label"] == "CRITICAL")
high = sum(1 for a in alerts if a["severity_label"] == "HIGH")
medium = sum(1 for a in alerts if a["severity_label"] == "MEDIUM")

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Alerts", total)
m2.metric("Critical", critical)
m3.metric("High", high)
m4.metric("Medium / Low", medium + sum(1 for a in alerts if a["severity_label"] == "LOW"))

# ---------------------------------------------------------------------------
# Severity distribution chart
# ---------------------------------------------------------------------------
if alerts:
    df = pd.DataFrame(alerts)
    counts = (
        df["severity_label"]
        .value_counts()
        .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        .fillna(0)
        .astype(int)
    )
    chart_df = pd.DataFrame({"Severity": counts.index, "Count": counts.values})
    st.bar_chart(chart_df.set_index("Severity"))

st.divider()

# ---------------------------------------------------------------------------
# Alert feed
# ---------------------------------------------------------------------------
st.subheader("📋 Alert Feed")

if not alerts:
    st.info("No alerts yet — use the sidebar to trigger a simulated GuardDuty finding.")
else:
    for alert in alerts:
        color = SEVERITY_COLORS[alert["severity_label"]]
        with st.container(border=True):
            header_col, badge_col = st.columns([5, 1])
            header_col.markdown(f"**{alert['title']}**")
            badge_col.markdown(
                f"""<span style="background-color:{color}; color:white; padding:2px 10px;
                border-radius:12px; font-size:12px; font-weight:600;">
                {alert['severity_label']} ({alert['severity_score']})</span>""",
                unsafe_allow_html=True,
            )
            st.caption(
                f"{alert['finding_type']}  •  {alert['resource']}  •  {alert['timestamp']}"
            )
            st.write(alert["description"])
            with st.expander("AI analysis + remediation steps"):
                st.markdown(f"**Analysis:** {alert['summary']}")
                st.markdown("**Recommended steps:**")
                for i, step in enumerate(alert["steps"], 1):
                    st.markdown(f"{i}. {step}")

st.divider()
st.caption(
    "Built with Python, AWS CloudTrail, GuardDuty, EventBridge, Lambda, and SNS. "
    "See the full source and one-command deployment on GitHub."
)
