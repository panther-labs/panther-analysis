# NOTE: Both "Optional" and "Override" functions will override YAML settings in the rule for a particular alert.

## Required Functions
def rule(event): # the logic for setting off an alert, return True = Alert, False = Do not Alert
    if event.get('Something'):
        return True
    return False

## Optional Functions
def title(event): # User can set custom alert titles in string format
    return 'This is my title'

def dedup(event): # by default if not defined the deduplication period string is based off the alert title 
    return 'DedupString'

def alert_context(event): # additional information that the user may find useful that is passed in with the alert as a dictionary
    return dict(event)

## Override Functions
def severity(event): # change the severity of the events based which can be used if a special condition is met  (str = "INFO", "LOW", "MEDIUM', "HIGH", "CRITICAL")
    return 'INFO'

def description(event): # customize the description to the specific event (str)
    return 'Some Alert Description'

def reference(event): # customize the reference to the specific event (str)
    return 'https://some.com/reference/url'

def runbook(event): # customize the runbook to the specific event (str)
    return 'If this happens, do this'

def destinations(event): # Override all destinations and route to specific destination list[str]
    if event.get('Something') in BAD_THINGS:
        return ['01234567-1edf-4edb-8f5b-0123456789a']
    # Suppress the alert
    else:
        return []