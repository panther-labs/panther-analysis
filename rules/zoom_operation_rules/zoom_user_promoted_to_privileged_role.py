import re

PRIVILEGED_ROLES = ("Admin", "Co-Owner", "Owner", "Billing Admin")


def extract_values(event):
    operator = event.get("operator", "<operator-not-found>")
    operation_detail = event.get("operation_detail", "")
    email = re.search(r"[\w.+-c]+@[\w-]+\.[\w.-]+", operation_detail)[0] or "<email-not-found>"
    fromto = re.findall(r"from ([-\w]+) to ([-\w]+)", operation_detail) or [
        ("<from-role-not-found>", "<to-role-not-found>")
    ]
    from_role, to_role = fromto[0] or ("<role-not-found>", "<role-not-found>")
    return operator, email, from_role, to_role


def rule(event):
    if (
        "Update" in event.get("action", "")
        and event.get("category_type") == "User"
        and event.get("operation_detail", "").startswith("Change Role")
    ):
        _, _, from_role, to_role = extract_values(event)
        return to_role in PRIVILEGED_ROLES and from_role not in PRIVILEGED_ROLES
    return False


def title(event):
    operator, email, from_role, to_role = extract_values(event)
    return (
        f"Zoom: [{email}]'s role was changed from [{from_role}] " f"to [{to_role}] by [{operator}]."
    )
