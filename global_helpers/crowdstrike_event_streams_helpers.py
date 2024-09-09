from panther_base_helpers import key_value_list_to_dict


def cs_alert_context(event):
    return audit_keys_dict(event)


def audit_keys_dict(event):
    return key_value_list_to_dict(
        event.deep_get("event", "AuditKeyValues", default=[]), "Key", "ValueString"
    )


def str_to_list(liststr: str) -> list[str]:
    """Several crowdstrike values are returned as a list like "[x y z]". This function convetrs
    such entries to Python list of strings, like: ["x", "y", "z"]."""
    # Return empty list for empty string
    if not liststr:
        return []
    # Validate
    if liststr[0] != "[" or liststr[-1] != "]":
        raise ValueError(f"Invalid list string: {liststr}")
    return [x.strip() for x in liststr[1:-1].split(" ")]
