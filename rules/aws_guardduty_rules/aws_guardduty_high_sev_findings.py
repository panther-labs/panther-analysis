from panther_base_helpers import aws_guardduty_context, deep_get


def rule(event):
    if deep_get(event, "additionalInfo", "sample"):
        # in case of sample data
        # https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html
        return False
    return 7.0 <= float(event.get("severity", 0)) <= 8.9


def dedup(event):
    return event.get("id")


def title(event):
    return event.get("title")


def alert_context(event):
    return aws_guardduty_context(event)
