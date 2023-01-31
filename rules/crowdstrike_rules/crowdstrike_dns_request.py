from panther_base_helpers import get_crowdstrike_field

# baddomain.com is present for testing purposes. Add domains you wish to be alerted on to this list
DENYLIST = ["baddomain.com"]


def rule(event):
    # We need to run either for Crowdstrike.DnsRequest or for DnsRequest.FDREvent with the
    # 'DnsRequest' fdr_event_type. Crowdstrike.DnsRequest is covered because of the
    # association with the type
    if (
        event.get("p_log_type") == "Crowdstrike.FDREvent"
        and event.get("fdr_event_type", "") != "DnsRequest"
    ):
        return False

    if get_crowdstrike_field(event, "DomainName") in DENYLIST:
        return True
    return False


def title(event):
    return (
        f"A denylisted domain [{get_crowdstrike_field(event, 'DomainName')}] was "
        + f"queried by host {event.get('aid')}"
    )


def dedup(event):
    #  Alert on every individual lookup of a bad domain, per machine
    return f"{get_crowdstrike_field(event, 'DomainName')}-{event.get('aid')}"
