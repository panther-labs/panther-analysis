import json


def rule(event):
    custom_message = event.deep_get("detail", "custom_message", default="")
    emails_raw = event.deep_get("detail", "target_details", default="")

    if custom_message != "Ask for password reset":
        return False

    try:
        emails = json.loads(emails_raw)
    except json.decoder.JSONDecodeError:
        return False

    if len(emails) > 1:
        return True
    return False


def title(event):
    emails = event.deep_get("detail", "target_details", default="")
    return f"[GitLab] Multiple password reset emails requested for {emails}"
