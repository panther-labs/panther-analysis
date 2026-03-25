from panther_databricks_helpers import databricks_alert_context


def rule(event):
    if event.get("actionName") != "createRecipient":
        return False

    # Check if IP access list is configured
    ip_access_list = event.deep_get("requestParams", "ipAccessList")

    # Alert if IP ACL is missing, empty string, or empty list
    if not ip_access_list:
        return True
    if isinstance(ip_access_list, str) and ip_access_list == "":
        return True
    if isinstance(ip_access_list, list) and len(ip_access_list) == 0:
        return True

    return False


def title(event):
    actor = event.deep_get("userIdentity", "email", default="Unknown Actor")
    recipient = event.deep_get("requestParams", "name", default="Unknown Recipient")
    return f"Delta Sharing recipient created without IP ACLs: {recipient} by {actor}"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={"recipient_name": event.deep_get("requestParams", "name")},
    )
