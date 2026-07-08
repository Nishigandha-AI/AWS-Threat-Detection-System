"""
Optional AI enrichment layer using Amazon Bedrock.

This module is only imported/used when the Lambda environment variable
USE_BEDROCK is set to "true". It sends the GuardDuty finding + the
static remediation guidance to a Bedrock foundation model and asks it
to produce a concise, plain-English risk summary and prioritized next
steps tailored to the specific finding.

Requires the Lambda execution role to include:
  bedrock:InvokeModel

on the target model ARN (see iam/lambda-execution-role-policy.json).
"""

import json
import os

import boto3

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
)

bedrock_runtime = boto3.client("bedrock-runtime")


def generate_ai_summary(finding: dict, remediation: dict) -> str:
    """
    Calls Amazon Bedrock to generate a natural-language analysis of the
    GuardDuty finding, using the static remediation KB entry as grounding
    context so the model doesn't hallucinate unrelated advice.
    """
    detail = finding.get("detail", {})

    prompt = f"""You are a cloud security analyst. A GuardDuty finding was
just generated. Summarize the risk in 2-3 sentences for a busy on-call
engineer, and highlight the single most urgent action to take first.

Finding type: {detail.get('type')}
Title: {detail.get('title')}
Severity: {detail.get('severity')}
Description: {detail.get('description')}

Known remediation steps for this finding category:
{json.dumps(remediation['steps'], indent=2)}

Respond in plain text, no markdown headers, under 120 words.
"""

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 300,
        "messages": [{"role": "user", "content": prompt}],
    }

    response = bedrock_runtime.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json",
    )

    payload = json.loads(response["body"].read())
    content_blocks = payload.get("content", [])
    text = "".join(block.get("text", "") for block in content_blocks)
    return text.strip() or remediation["summary"]
