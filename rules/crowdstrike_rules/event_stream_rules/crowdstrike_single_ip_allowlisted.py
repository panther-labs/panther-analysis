from crowdstrike_event_streams_helpers import audit_keys_dict, cs_alert_context


def get_single_ips(event) -> list[str]:
    """Searches the "cidrs" field of the event audit keys, and returns any cidr entries which
    are actually just single IP addresses."""
    single_ips = []
    audit_keys = audit_keys_dict(event)
    cidrs = str_to_list(audit_keys["cidrs"])
    for entry in cidrs:
        if "/" not in entry:
            single_ips.append(entry)
        elif entry.endswith("/32"):
            # A 32-bit CIDR range is the same as a single IP address
            single_ips.append(entry[:-3])
    return single_ips


def str_to_list(liststr: str) -> list[str]:
    """Several crowdstrike values are returned as a list like "[x,y,z]". This function convetrs
    such entries to Python list of strings, like: ["x", "y", "z"]."""
    return [x.strip() for x in liststr[1:-1].split(",")]


def rule(event):
    # Only alert if an allow list is created
    if event.deep_get("event", "OperationName") != "CreateAllowlistGroup":
        return False

    # Only alert if there's a single IP address allowed by the allowlist
    single_ips = get_single_ips(event)

    # Return true if there were any single IPs
    return len(single_ips) > 0


def title(event):
    # Title format: {actor} granted {contexts_str} access to {a, X} single ip{s}
    single_ips = get_single_ips(event)
    actor = event.deep_get("event", "UserId")

    # contexts_str: one of API, UI, or API & UI
    #   Also a more general case: API, UI, and XX (for if they add extra contexts in the future)
    contexts = str_to_list(audit_keys_dict(event)["contexts"])
    if len(contexts) == 1:
        contexts_str = contexts[0]
    else:
        contexts_str = ", ".join(contexts[:-1]) + " & " + contexts[-1]

    num_ips_str = "a single ip" if len(contexts) == 1 else f"{len(single_ips)} single ips"

    return f"{actor} granted {contexts_str} access to {num_ips_str}"


def alert_context(event):
    context = cs_alert_context(event)
    context.update({"single_ips": get_single_ips(event)})
    return context
