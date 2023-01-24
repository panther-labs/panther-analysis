from panther_base_helpers import deep_get, get_crowdstrike_field

# baddomain.com is present for testing purposes. Add domains you wish to be alerted on to this list
DENYLIST = ["baddomain.com"]


def rule(event):
    if get_crowdstrike_field(event, "DomainName") in DENYLIST:
        return True
    return False


def title(event):
    return f"A denylisted domain [{get_crowdstrike_field(event, 'DomainName')}] was queried by host {event.get('aid')}"


def dedup(event):
    #  Alert on every individual lookup of a bad domain, per machine
    return f"{get_crowdstrike_field(event, 'DomainName')}-{event.get('aid')}"
