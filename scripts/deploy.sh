#!/usr/bin/env bash
#
# Deploys the AWS Threat Detection System end-to-end:
#   1. Packages the Lambda source into a zip.
#   2. Deploys/updates the CloudFormation stack (CloudTrail, GuardDuty,
#      EventBridge rule, Lambda function shell, SNS topic + subscriptions).
#   3. Updates the deployed Lambda function with the real source code.
#
# Usage:
#   ./scripts/deploy.sh <notification-email> [phone-number] [aws-region]
#
# Example:
#   ./scripts/deploy.sh you@example.com +15551234567 us-east-1
#
set -euo pipefail

STACK_NAME="threat-detection-system"
REGION="${3:-us-east-1}"
EMAIL="${1:?Usage: deploy.sh <email> [phone] [region]}"
PHONE="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
LAMBDA_DIR="$ROOT_DIR/lambda"
TEMPLATE_FILE="$ROOT_DIR/infrastructure/cloudformation/template.yaml"
BUILD_DIR="$ROOT_DIR/.build"
ZIP_FILE="$BUILD_DIR/threat_processor.zip"

echo "==> Checking AWS CLI credentials..."
aws sts get-caller-identity --region "$REGION" >/dev/null

echo "==> Packaging Lambda function..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp "$LAMBDA_DIR/threat_processor.py" "$BUILD_DIR/"
cp "$LAMBDA_DIR/enrichment.py" "$BUILD_DIR/"
(cd "$BUILD_DIR" && zip -q -r "$(basename "$ZIP_FILE")" ./*.py)

echo "==> Deploying CloudFormation stack: $STACK_NAME ..."
aws cloudformation deploy \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$TEMPLATE_FILE" \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      NotificationEmail="$EMAIL" \
      NotificationPhoneNumber="$PHONE"

echo "==> Fetching deployed Lambda function name..."
FUNCTION_NAME=$(aws cloudformation describe-stacks \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='LambdaFunctionName'].OutputValue" \
  --output text)

echo "==> Updating Lambda function code: $FUNCTION_NAME ..."
aws lambda update-function-code \
  --region "$REGION" \
  --function-name "$FUNCTION_NAME" \
  --zip-file "fileb://$ZIP_FILE" \
  >/dev/null

echo "==> Waiting for function update to complete..."
aws lambda wait function-updated \
  --region "$REGION" \
  --function-name "$FUNCTION_NAME"

echo ""
echo "Deployment complete."
echo "  - Confirm the SNS email subscription in your inbox (check for a"
echo "    'AWS Notification - Subscription Confirmation' email) or the alert"
echo "    will not be delivered."
echo "  - If you provided a phone number, SMS delivery is active immediately."
echo "  - Trigger scripts/test_lambda.py or scripts/simulate_finding.sh to"
echo "    generate a sample GuardDuty finding and confirm end-to-end delivery."
