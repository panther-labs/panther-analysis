from crowdstrike_event_streams_helpers import audit_keys_dict, cs_alert_context, str_to_list


def rule(event):
    # Only alert if an allow list is created or edited
    op_name = event.deep_get("event", "OperationName")
    if op_name not in ("CreateAllowlistGroup", "UpdateAllowlistGroup"):
        return False

    return True


def title(event):
    actor = event.deep_get("event", "UserId")
    action = {
        "CreateAllowlistGroup": "created a new",
        "UpdateAllowlistGroup": "made changes to",
    }.get(event.deep_get("event", "OperationName"))
    group = audit_keys_dict(event).get("group_name", "UNKNWOWN GROUP")
    return f"{actor} {action} Crowdstrike IP allowlist group: {group}"


def alert_context(event):
    context = cs_alert_context(event)

    # Be nice and concert the "lists" into actual lists so customers can easily process the alert
    #   context
    for key in ("cidrs", "old_cidrs", "contexts", "old_contexts"):
        if context.get(key):
            try:
                context[key] = str_to_list(context[key])
            except ValueError:
                pass  # Just ignore if we can't unmarshal it

    # Find out what entries were removed, and which were added
    op_name = event.deep_get("event", "OperationName")
    audit_keys = audit_keys_dict(event)
    added_cidrs = []
    removed_cidrs = []
    added_contexts = []
    removed_contexts = []

    def getlist(key: str):
        return str_to_list(audit_keys.get(key))

    match op_name:
        case "UpdateAllowlistGroup":
            new_cidrs = getlist("cidrs")
            old_cidrs = getlist("old_cidrs")
            new_ctx = getlist("contexts")
            old_ctx = getlist("old_contexts")
            added_cidrs = get_unique_entries(new_cidrs, old_cidrs)
            removed_cidrs = get_unique_entries(old_cidrs, new_cidrs)
            added_contexts = get_unique_entries(new_ctx, old_ctx)
            removed_contexts = get_unique_entries(old_ctx, new_ctx)
        case "CreateAllowlistGroup":
            added_cidrs = str_to_list(audit_keys.get("cidrs", []))
            added_contexts = str_to_list(audit_keys.get("contexts", []))
        case _:
            # Raise error if there's another operationname
            #   This is in case we update the rule logic but forget to update this logic too
            raise ValueError(f"Unepected Operation Name: {op_name}")

    context.update(
        {
            "changes": {
                "cidr_added": added_cidrs,
                "cidr_removed": removed_cidrs,
                "context_added": added_contexts,
                "context_removed": removed_contexts,
            }
        }
    )

    return context


def get_unique_entries(list1: list, list2: list) -> list:
    """Returns items in l1 that are not in l2."""
    return list(set(list1) - set(list2))
