# NOTE: Both "Optional" and "Override" functions will override YAML settings in the rule for a
# particular alert.

## Required Function
# The logic for sending an alert, return True = Alert, False = Do not Alert
def rule(event):
    if event.get("Something"):
        return True
    return False


## Optional Functions
# Set custom alert titles, must return a string
# If not defined, defaults to the rule display name or ID
def title(event):
    return "This is my title " + event.get("Something")


# Set custom deduplication strings, must return a string
# If not defined, defaults to the alert title
def dedup(event):
    return "DedupString:" + event.get("Something")


# Additional information append to an alert, must return a dictionary
def alert_context(event):
    return dict(event)


## Override Functions
# Override the severity of an alert based on the contents of the events,
# must return one of the following strings "INFO", "LOW", "MEDIUM', "HIGH", "CRITICAL"
def severity(event):
    if event.get("Something"):
        return "INFO"
    return "HIGH"


# Override the description of the alert, must return a string
def description(event):
    return "Some Alert Description " + event.get("Something")


# Override the reference in the alert, must return a string
def reference(event):
    return "https://some.com/reference/" + event.get("Something")


# Override the runbook in the alert, must return a string
def runbook(event):
    return "If this happens, do " + event.get("Something")


# Override the destination(s) the alert is sent to, must return a list of strings corresponding to
# panther destinations
BAD_THINGS = []
def destinations(event):
    if event.get("Something") in BAD_THINGS:
        return ["01234567-1edf-4edb-8f5b-0123456789a"]
    # Suppress the alert
    return []
