#!/usr/bin/env bash
#
# Tears down the AWS Threat Detection System stack.
#
# Usage:
#   ./scripts/destroy.sh [aws-region]
#
set -euo pipefail

STACK_NAME="threat-detection-system"
REGION="${1:-us-east-1}"

echo "This will delete the CloudFormation stack '$STACK_NAME' in region '$REGION'."
echo "Note: the CloudTrail S3 log bucket is retained (DeletionPolicy: Retain)"
echo "and must be emptied/deleted manually if you no longer need the logs."
read -r -p "Continue? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

aws cloudformation delete-stack --region "$REGION" --stack-name "$STACK_NAME"
echo "==> Waiting for stack deletion to complete..."
aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$STACK_NAME"
echo "Stack deleted."
