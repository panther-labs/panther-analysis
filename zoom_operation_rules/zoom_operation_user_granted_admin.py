from panther_zoom_helpers import get_zoom_user_context as get_context


def rule(event):
    if event.get("category_type") != "User" and event.get("Action") == "Update":
        return False

    context = get_context(event)

    if "Member to Admin" in context["Change"]:
        return True
    return False


def title(event):
    context = get_context(event)

    return f"Zoom User {context['User']} was made an admin by {event.get('operator')}"
