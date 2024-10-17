from panther_aws_helpers import aws_guardduty_context


def rule(event):
    if event.deep_get("service", "additionalInfo", "sample"):
        # in case of sample data
        # https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html
        return False
    return 4.0 <= float(event.get("severity", 0)) <= 6.9


def title(event):
    return event.get("title")


def alert_context(event):
    return aws_guardduty_context(event)
