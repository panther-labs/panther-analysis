from panther_base_helpers import aws_guardduty_context


def rule(event):
    if deep_get(event, "additionalInfo", "sample") == True:
        return False  # in case of sample data https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html
    else:
        return 0.1 <= float(event.get("severity", 0)) <= 3.9


def dedup(event):
    return event.get("id")


def title(event):
    return event.get("title")


def alert_context(event):
    return aws_guardduty_context(event)
