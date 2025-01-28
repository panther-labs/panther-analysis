from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

GUARDRAIL_EVENTS = {"DeleteGuardrail", "UpdateGuardrail"}


def rule(event):
    if (
        event.get("eventSource") == "bedrock.amazonaws.com"
        and event.get("eventName") in GUARDRAIL_EVENTS
        and aws_cloudtrail_success(event)
    ):
        return True
    return False


def title(event):
    user = event.udm("actor_user")
    guardrail = event.deep_get("requestParameters", "guardrailIdentifier")
    action = event.get("eventName").replace("Guardrail", "").lower()
    return f"User [{user}] {action}d Bedrock guardrail [{guardrail}]"


def severity(event):
    if event.get("eventName") == "UpdateGuardrail":
        return "LOW"
    return "DEFAULT"


def alert_context(event):
    return aws_rule_context(event)
