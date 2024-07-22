from panther_base_helpers import key_value_list_to_dict


def cs_alert_context(event):
    return audit_keys_dict(event)

def audit_keys_dict(event):
    return key_value_list_to_dict(
        event.deep_get("event", "AuditKeyValues", default=[]), "Key", "ValueString"
    )
