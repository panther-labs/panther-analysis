from panther_zoom_helpers import get_zoom_user_context as get_context


def rule(event):
    if event.get("Action") != "Update" or event.get("category_type") != "User":
        return False

    context = get_context(event)

    return "Member to Admin" in context["Change"]


def title(event):
    context = get_context(event)

    return f"Zoom User {context['User']} was made an admin by {event.get('operator')}"
