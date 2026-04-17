from panther_base_helpers import pattern_match


## Required
#
# The logic to determine if an alert should send.
# return True = Alert, False = Do not Alert
def rule(event):
    return event.get("field") == "value" and event.deep_get("field", "nestedValue")


## Optional Functions
#
# Set custom alert titles, must return a string.
# If not defined, defaults to the rule display name or rule ID.
def title(event):
    if pattern_match(event.get("field"), "string*"):
        return f"This is my alert title {event.get('field')}"
    return f"This is my fallback title {event.get('field')}"


# Set custom deduplication strings, must return a string.
# If not defined, defaults to the alert title.
def dedup(event):
    return event.get("identity")


# Additional information append to an alert, must return a dictionary
def alert_context(event):
    return {
        "someField": event.get("someField"),
        "someRandomValue": 4,  # chosen by a dice roll, guaranteed to be random
    }


## Override Functions
#
# Override the severity of an alert based on the contents of the events,
# must return one of the following strings "INFO", "LOW", "MEDIUM', "HIGH", "CRITICAL"
def severity(event):
    if event.get("field") == "value":
        return "INFO"
    return "HIGH"


# Override the description of the alert, must return a string
def description(event):
    return f"Some Alert Description {event.get('Something')}"


# Override the reference in the alert, must return a string
def reference(event):
    return f"https://some.com/reference/{event.get('Something')}"


# Override the runbook in the alert, must return a string
def runbook(event):
    return f"If this happens, do {event.get('Something')}"


# Override the destination(s) the alert is sent to, must return a list of strings corresponding to
# panther destinations
BAD_THINGS = []


def destinations(event):
    if event.get("Something") in BAD_THINGS:
        return ["01234567-1edf-4edb-8f5b-0123456789a"]
    # Suppress the alert
    return []
