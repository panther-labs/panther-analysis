def rule(event):
    if event.get("name") != "change_owner":
        return False

    if event.deep_get("parameters", "visibility") in (
        "shared_internally",
        "people_within_domain_with_link",
        "private",
    ):
        return False

    previous_owner = event.deep_get("parameters", "owner", default="<UNKNOWN USER>")
    new_owner = event.deep_get("parameters", "new_owner", default="<UNKNOWN USER>")

    previous_owner_domain = previous_owner.split("@")[1] if "@" in previous_owner else None
    new_owner_domain = new_owner.split("@")[1] if "@" in new_owner else None

    if previous_owner_domain is None or new_owner_domain is None:
        return False

    if previous_owner_domain != new_owner_domain:
        return True

    return False


def title(event):
    actor = event.deep_get("actor", "email", default="<UNKNOWN USER>")
    previous_owner = event.deep_get("parameters", "owner", default="<UNKNOWN USER>")
    new_owner = event.deep_get("parameters", "new_owner", default="<UNKNOWN USER>")

    return f"User [{actor}] transferred document ownership from [{previous_owner}] to [{new_owner}]"
