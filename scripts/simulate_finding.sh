#!/usr/bin/env bash
#
# Triggers GuardDuty's built-in sample findings generator, which creates
# one sample finding for every finding type GuardDuty supports. Within a
# few minutes, EventBridge should route these to the Lambda function and
# you should receive Email/SMS alerts (subject to MIN_SEVERITY filtering).
#
# Usage:
#   ./scripts/simulate_finding.sh [aws-region]
#
set -euo pipefail

REGION="${1:-us-east-1}"

DETECTOR_ID=$(aws guardduty list-detectors --region "$REGION" --query "DetectorIds[0]" --output text)

if [[ "$DETECTOR_ID" == "None" || -z "$DETECTOR_ID" ]]; then
  echo "No GuardDuty detector found in region $REGION. Deploy the stack first."
  exit 1
fi

echo "==> Generating GuardDuty sample findings for detector $DETECTOR_ID ..."
aws guardduty create-sample-findings --region "$REGION" --detector-id "$DETECTOR_ID"

echo "Done. Sample findings generated. Check your email/SMS in a few minutes,"
echo "and check CloudWatch Logs for the Lambda function for processing details:"
echo "  aws logs tail /aws/lambda/guardduty-threat-processor --region $REGION --follow"
