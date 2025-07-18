import re


def rule(event):
    if all(
        [
            event.deep_get("legacyeventtype", default="") == "core.user_auth.login_failed",
            not re.match(
                r"(^0oa.*|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,10})",
                event.deep_get("actor", "alternateid", default=""),
            ),
        ]
    ):
        return True
    return False
