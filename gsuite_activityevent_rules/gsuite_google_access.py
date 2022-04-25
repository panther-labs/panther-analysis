from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "id", "applicationName") != "access_transparency":
        return False

    return bool(event.get("type") == "GSUITE_RESOURCE")
