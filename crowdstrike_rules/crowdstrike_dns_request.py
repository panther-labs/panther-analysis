# baddomain.com is present for testing purposes. Add domains you wish to be alerted on to this list
DENYLIST = ["baddomain.com"]


def rule(event):
    if event.get("DomainName") in DENYLIST:
        return True
    return False


def title(event):
    return f"A denylisted domain [{event.get('DomainName')}] was queried by host {event.get('aid')}"


def dedup(event):
    #  Alert on every individual lookup of a bad domain, per machine
    return f"{event.get('timestamp')} {event.get('DomainName')} {event.get('aid')}"
