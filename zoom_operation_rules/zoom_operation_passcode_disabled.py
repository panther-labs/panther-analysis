from panther_zoom_helpers import get_zoom_usergroup_context as get_context


def rule(event):
    if event.get("category_type") != "User Group":
        return False

    context = get_context(event)
    if "Passcode" in context["Change"] and context["DisabledSetting"]:
        return True
    return False


def title(event):
    context = get_context(event)

    return f"Group {context['GroupName']} passcode requirement disabled by {event.get('operator')}"
