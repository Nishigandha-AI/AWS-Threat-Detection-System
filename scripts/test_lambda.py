#!/usr/bin/env python3
"""
Invokes the deployed Lambda function directly with a sample GuardDuty
EventBridge event, useful for testing the pipeline without waiting on
GuardDuty's sample-finding generator.

Usage:
    python3 scripts/test_lambda.py [function-name] [region]
"""
import json
import sys

import boto3

FUNCTION_NAME = sys.argv[1] if len(sys.argv) > 1 else "guardduty-threat-processor"
REGION = sys.argv[2] if len(sys.argv) > 2 else "us-east-1"

SAMPLE_EVENT = {
    "version": "0",
    "id": "test-event-id",
    "detail-type": "GuardDuty Finding",
    "source": "aws.guardduty",
    "account": "123456789012",
    "region": REGION,
    "detail": {
        "schemaVersion": "2.0",
        "accountId": "123456789012",
        "region": REGION,
        "id": "test-finding-id",
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "title": "IAM credentials exfiltrated to an external IP address",
        "description": "Credentials for IAM user 'test-user' were used from "
                        "an IP address outside your AWS account and are "
                        "believed to be compromised.",
        "severity": 8.0,
        "resource": {
            "resourceType": "AccessKey",
            "instanceDetails": {"instanceId": "N/A"},
        },
    },
}


def main():
    client = boto3.client("lambda", region_name=REGION)
    print(f"Invoking {FUNCTION_NAME} in {REGION} with a sample finding...")

    response = client.invoke(
        FunctionName=FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(SAMPLE_EVENT).encode("utf-8"),
    )

    payload = json.loads(response["Payload"].read())
    print("Response:")
    print(json.dumps(payload, indent=2))

    if response.get("FunctionError"):
        print(f"\nFunction returned an error: {response['FunctionError']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
