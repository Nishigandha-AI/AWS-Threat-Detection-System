"""
AWS AI-Powered Threat Detection System
----------------------------------------
Lambda function triggered by EventBridge whenever GuardDuty publishes a
new finding. The function:

  1. Parses the raw GuardDuty finding delivered by EventBridge.
  2. Enriches the finding with human-readable context and remediation
     guidance (a lightweight rules-engine that mimics "AI-assisted"
     triage -- see enrichment.py for how to swap in a real Bedrock/LLM
     call).
  3. Formats a clean, readable alert message.
  4. Publishes the alert to an SNS topic, which fans out to Email + SMS
     subscribers.

Environment Variables:
  SNS_TOPIC_ARN      - ARN of the SNS topic to publish alerts to
  MIN_SEVERITY        - (optional) Minimum GuardDuty severity to alert on
                         (default: 4.0 -> Medium and above)
  USE_BEDROCK          - (optional) "true" to call Amazon Bedrock for an
                         AI-generated remediation summary instead of the
                         static rules engine (default: "false")
  BEDROCK_MODEL_ID     - (optional) Bedrock model id, defaults to a
                         Claude model on Bedrock
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_client = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
MIN_SEVERITY = float(os.environ.get("MIN_SEVERITY", "4.0"))
USE_BEDROCK = os.environ.get("USE_BEDROCK", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Static "rules engine" remediation knowledge base.
# Keyed by GuardDuty finding "type" prefix -> human guidance.
# This acts as the fallback / default enrichment source and is what runs
# when USE_BEDROCK is false. See enrichment.py for the Bedrock-based
# AI enrichment path.
# ---------------------------------------------------------------------------
REMEDIATION_KB = {
    "CryptoCurrency": {
        "summary": "An EC2 instance or workload is communicating with a "
                    "known cryptocurrency mining pool.",
        "steps": [
            "Isolate the affected instance by removing it from all "
            "security groups or applying a deny-all security group.",
            "Snapshot the instance's EBS volume for forensic analysis "
            "before termination.",
            "Terminate the compromised instance once evidence is captured.",
            "Rotate any IAM credentials or instance profile roles "
            "attached to the instance.",
            "Review CloudTrail for the API calls that launched the "
            "instance to identify the initial access vector.",
        ],
    },
    "UnauthorizedAccess": {
        "summary": "API activity or console login matches patterns "
                    "associated with unauthorized or brute-force access.",
        "steps": [
            "Disable or rotate the credentials (IAM user/role) involved.",
            "Enable / enforce MFA on the affected IAM identity.",
            "Review CloudTrail Event history for the identity's recent "
            "activity to scope the blast radius.",
            "If the source IP is unexpected, block it via a Security "
            "Group / NACL / WAF rule.",
            "Consider enabling AWS IAM Access Analyzer to review "
            "resource policies for unintended public exposure.",
        ],
    },
    "Backdoor": {
        "summary": "An EC2 instance may be compromised and is exhibiting "
                    "backdoor / command-and-control behavior.",
        "steps": [
            "Isolate the instance immediately (quarantine security group).",
            "Capture a memory/disk snapshot for forensics.",
            "Terminate and rebuild the instance from a known-good AMI.",
            "Rotate all credentials and secrets the instance had access to.",
            "Patch the AMI / golden image and redeploy.",
        ],
    },
    "Trojan": {
        "summary": "A host is showing signs of malware / trojan activity "
                    "(e.g., DNS exfiltration, blackhole traffic).",
        "steps": [
            "Isolate the affected instance from the network.",
            "Run a full malware scan / forensic snapshot.",
            "Rotate credentials associated with the instance.",
            "Rebuild from a hardened, patched image.",
        ],
    },
    "Recon": {
        "summary": "Reconnaissance activity detected (e.g., port scanning "
                    "or unusual API enumeration).",
        "steps": [
            "Review Security Group / NACL rules for unnecessary open "
            "ports.",
            "Confirm the source is not an authorized vulnerability scan.",
            "Block the offending source IP if malicious.",
            "Enable VPC Flow Logs if not already enabled for deeper "
            "visibility.",
        ],
    },
    "Policy": {
        "summary": "A security best-practice / policy violation was "
                    "detected (e.g., root account usage, S3 exposure).",
        "steps": [
            "Review the specific resource/action flagged in the finding.",
            "Apply least-privilege corrections to the IAM policy / "
            "resource policy involved.",
            "Enable AWS Config rules to prevent recurrence.",
        ],
    },
    "Exfiltration": {
        "summary": "Data exfiltration behavior detected from a resource "
                    "in your account.",
        "steps": [
            "Isolate the affected resource immediately.",
            "Identify and revoke the credentials used.",
            "Review S3 / RDS / EC2 data access logs for scope of data "
            "accessed.",
            "Notify your incident response / compliance team.",
        ],
    },
    "Impact": {
        "summary": "A resource in your account appears to be impacted "
                    "and may be actively used to attack others.",
        "steps": [
            "Isolate the resource immediately to stop outbound attacks.",
            "Capture forensic evidence before remediation.",
            "Rebuild the resource from a trusted image.",
        ],
    },
}

DEFAULT_REMEDIATION = {
    "summary": "GuardDuty detected suspicious activity that does not map "
                "to a known category in the local knowledge base.",
    "steps": [
        "Review the full finding detail in the GuardDuty console.",
        "Correlate with CloudTrail logs around the finding timestamp.",
        "Escalate to your security team if severity is High or Critical.",
    ],
}


def get_remediation(finding_type: str) -> dict:
    """Look up remediation guidance by matching the finding type prefix."""
    for key, remediation in REMEDIATION_KB.items():
        if finding_type.startswith(key):
            return remediation
    return DEFAULT_REMEDIATION


def severity_label(score: float) -> str:
    if score >= 7.0:
        return "CRITICAL"
    if score >= 4.0:
        return "HIGH"
    if score >= 1.0:
        return "MEDIUM"
    return "LOW"


def build_ai_enrichment(finding: dict, remediation: dict) -> str:
    """
    Optionally call Amazon Bedrock to generate a natural-language,
    context-aware remediation summary instead of the static KB text.
    Falls back silently to the static remediation on any error.
    """
    if not USE_BEDROCK:
        return remediation["summary"]

    try:
        from enrichment import generate_ai_summary  # local import, optional dep
        return generate_ai_summary(finding, remediation)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Bedrock enrichment failed, using static KB: %s", exc)
        return remediation["summary"]


def format_alert_message(finding: dict) -> tuple[str, str]:
    """Build the (subject, body) tuple for the SNS notification."""
    detail = finding.get("detail", {})

    finding_type = detail.get("type", "Unknown")
    severity = float(detail.get("severity", 0))
    title = detail.get("title", "GuardDuty Finding")
    description = detail.get("description", "No description provided.")
    account_id = finding.get("account", "unknown")
    region = finding.get("region", "unknown")
    finding_id = detail.get("id", "unknown")

    resource = detail.get("resource", {})
    resource_type = resource.get("resourceType", "N/A")
    instance_details = resource.get("instanceDetails", {})
    instance_id = instance_details.get("instanceId", "N/A")

    remediation = get_remediation(finding_type)
    ai_summary = build_ai_enrichment(finding, remediation)

    level = severity_label(severity)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    subject = f"[{level}] GuardDuty Alert: {finding_type}"[:100]  # SNS subject limit

    steps_formatted = "\n".join(f"  {i}. {s}" for i, s in enumerate(remediation["steps"], 1))

    body = f"""
AWS THREAT DETECTION ALERT
===========================
Severity     : {level} ({severity})
Finding Type : {finding_type}
Title        : {title}
Account      : {account_id}
Region       : {region}
Resource     : {resource_type} ({instance_id})
Finding ID   : {finding_id}
Detected At  : {timestamp}

DESCRIPTION
-----------
{description}

AI / AUTOMATED ANALYSIS
------------------------
{ai_summary}

RECOMMENDED REMEDIATION STEPS
------------------------------
{steps_formatted}

--
This alert was generated automatically by the AWS Threat Detection
pipeline (CloudTrail -> GuardDuty -> EventBridge -> Lambda -> SNS).
"""
    return subject, body.strip()


def handler(event, context):
    """Lambda entrypoint invoked by the EventBridge rule."""
    logger.info("Received event: %s", json.dumps(event))

    if not SNS_TOPIC_ARN:
        logger.error("SNS_TOPIC_ARN environment variable is not set.")
        raise RuntimeError("SNS_TOPIC_ARN environment variable is not set.")

    detail = event.get("detail", {})
    severity = float(detail.get("severity", 0))

    if severity < MIN_SEVERITY:
        logger.info(
            "Finding severity %.1f is below MIN_SEVERITY threshold %.1f; skipping alert.",
            severity, MIN_SEVERITY,
        )
        return {"statusCode": 200, "body": "Below severity threshold, no alert sent."}

    subject, message = format_alert_message(event)

    response = sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message,
    )

    logger.info("Published alert to SNS. MessageId=%s", response.get("MessageId"))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Alert published successfully",
            "sns_message_id": response.get("MessageId"),
        }),
    }
