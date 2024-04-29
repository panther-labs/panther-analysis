from panther_base_helpers import deep_get
from panther_core.immutable import ImmutableList


def rule(event):
    path = event.get("path", default="")

    if path != "/users/password":
        return False

    params = event.get("params", default=[])
    for param in params:
        if param.get("key") == "user":
            email = deep_get(param, "value", "email", default=[])
            if isinstance(email, ImmutableList) and len(email) > 1:
                return True
    return False


def title(event):
    emails = event.deep_get("detail", "target_details", default="")
    return f"Someone tried to reset your password with multiple emails :{emails}"
