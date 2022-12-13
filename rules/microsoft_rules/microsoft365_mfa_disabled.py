import json

from panther_base_helpers import m365_alert_context


def rule(event):
    if event.get("Operation", "") == "Update user.":
        modified_properties = event.get("ModifiedProperties", [])
        for prop in modified_properties:
            if prop.get("Name", "") == "StrongAuthenticationMethod":
                new_value = prop.get("NewValue")
                old_value = prop.get("OldValue")
                if isinstance(new_value, str):
                    new_value = json.loads(new_value)
                if isinstance(old_value, str):
                    old_value = json.loads(old_value)

                if old_value and not new_value:
                    return True
                break
    return False


def title(event):
    return "Microsoft365: MFA Removed on " f"[{event.get('ObjectId', '')}]"


def alert_context(event):
    return m365_alert_context(event)
