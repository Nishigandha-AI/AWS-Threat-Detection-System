"""
Unit tests for threat_processor.py

Run with:
    pip install boto3 moto pytest --break-system-packages
    pytest test_threat_processor.py -v
"""

import json
import os
import sys

import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(__file__))

SAMPLE_EVENT = {
    "version": "0",
    "id": "abcd1234-5678-90ab-cdef-1234567890ab",
    "detail-type": "GuardDuty Finding",
    "source": "aws.guardduty",
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {
        "schemaVersion": "2.0",
        "accountId": "123456789012",
        "region": "us-east-1",
        "id": "70b3xxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "title": "Bitcoin-related activity detected on EC2 instance",
        "description": "EC2 instance i-0123456789abcdef0 is querying a "
                        "domain name associated with cryptocurrency mining.",
        "severity": 8.5,
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0123456789abcdef0"},
        },
    },
}


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-topic")
    monkeypatch.setenv("MIN_SEVERITY", "4.0")
    monkeypatch.setenv("USE_BEDROCK", "false")


def test_severity_label():
    import threat_processor as tp
    assert tp.severity_label(8.0) == "CRITICAL"
    assert tp.severity_label(5.0) == "HIGH"
    assert tp.severity_label(2.0) == "MEDIUM"
    assert tp.severity_label(0.5) == "LOW"


def test_get_remediation_known_type():
    import threat_processor as tp
    remediation = tp.get_remediation("CryptoCurrency:EC2/BitcoinTool.B!DNS")
    assert "cryptocurrency mining pool" in remediation["summary"]
    assert len(remediation["steps"]) > 0


def test_get_remediation_unknown_type_uses_default():
    import threat_processor as tp
    remediation = tp.get_remediation("SomeBrandNewFindingType")
    assert remediation == tp.DEFAULT_REMEDIATION


def test_format_alert_message_contains_key_fields():
    import threat_processor as tp
    subject, body = tp.format_alert_message(SAMPLE_EVENT)
    assert "CRITICAL" in subject
    assert "CryptoCurrency" in body
    assert "i-0123456789abcdef0" in body
    assert "RECOMMENDED REMEDIATION STEPS" in body


@patch("threat_processor.sns_client")
def test_handler_publishes_to_sns_when_above_threshold(mock_sns):
    import threat_processor as tp
    mock_sns.publish.return_value = {"MessageId": "test-message-id"}

    result = tp.handler(SAMPLE_EVENT, None)

    mock_sns.publish.assert_called_once()
    call_kwargs = mock_sns.publish.call_args.kwargs
    assert call_kwargs["TopicArn"] == "arn:aws:sns:us-east-1:123456789012:test-topic"
    assert "CryptoCurrency" in call_kwargs["Message"]
    assert result["statusCode"] == 200


@patch("threat_processor.sns_client")
def test_handler_skips_low_severity(mock_sns):
    import threat_processor as tp
    low_severity_event = json.loads(json.dumps(SAMPLE_EVENT))
    low_severity_event["detail"]["severity"] = 1.0

    result = tp.handler(low_severity_event, None)

    mock_sns.publish.assert_not_called()
    assert "Below severity threshold" in result["body"]


def test_handler_raises_without_topic_arn(monkeypatch):
    monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)
    import importlib
    import threat_processor as tp
    importlib.reload(tp)

    with pytest.raises(RuntimeError):
        tp.handler(SAMPLE_EVENT, None)

    # restore for other tests
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-topic")
    importlib.reload(tp)
