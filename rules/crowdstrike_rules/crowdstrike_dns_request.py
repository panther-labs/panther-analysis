from panther_base_helpers import filter_crowdstrike_fdr_event_type, get_crowdstrike_field

# baddomain.com is present for testing purposes. Add domains you wish to be alerted on to this list
DENYLIST = ["baddomain.com"]


def rule(event):
    # We need to run either for Crowdstrike.DnsRequest or for Crowdstrike.FDREvent with the
    # 'DnsRequest' fdr_event_type. Crowdstrike.DnsRequest is covered because of the
    # association with the type
    if filter_crowdstrike_fdr_event_type(event, "DnsRequest"):
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
