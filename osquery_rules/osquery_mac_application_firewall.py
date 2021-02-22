from panther_base_helpers import deep_get

QUERIES = {"pack_incident-response_alf", "pack/mac-cis/ApplicationFirewall"}


def rule(event):
    if event.get("name") not in QUERIES:
        return False

    if event.get("action") != "added":
        return False

    return (
        # 0 If the firewall is disabled
        # 1 If the firewall is enabled with exceptions
        # 2 If the firewall is configured to block all incoming connections
        int(deep_get(event, "columns", "global_state")) == 0
        or
        # Stealth mode is a best practice to avoid responding to unsolicted probes
        int(deep_get(event, "columns", "stealth_enabled")) == 0
    )


def title(event):
    return "MacOS firewall disabled on [{}]".format(event.get("hostIdentifier"))
