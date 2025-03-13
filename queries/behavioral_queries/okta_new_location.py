from panther_detection_helpers.caching import get_dictionary

EVENT_TYPES = ("user.authentication.sso", "user.session.start")
GRANULARITY = ("country", "state", "city", "ipAddress")
PREFIX = "Okta.LocationBehavior|"
behavior, current = {}, {}


def rule(event):
    if event.get("eventType") not in EVENT_TYPES:
        return False

    global behavior, current
    key = PREFIX + event.deep_get("actor", "alternateId", default="")
    behavior = get_dictionary(key)
    current = event.deep_get("client", "geographicalContext", default={})

    return any(current.get(g) not in behavior.get(g, []) for g in GRANULARITY)


def title(event):
    for g in GRANULARITY:
        if current.get(g) not in behavior.get(g, []):
            return f'[{event.deep_get("actor", "alternateId", default="")}] logged in from new [{g}] [{current.get(g)}]'
    return '' # this should never happen


def severity(_):
    if current.get("country") not in behavior.get("country", []):
        return "High"
    if current.get("state") not in behavior.get("state", []):
        return "Medium"
    if current.get("city") not in behavior.get("city", []):
        return "Low"
    return "Info"
