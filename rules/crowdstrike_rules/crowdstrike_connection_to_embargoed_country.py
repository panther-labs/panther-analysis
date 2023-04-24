from panther_base_helpers import deep_get, crowdstrike_detection_alert_context

EMBARGO_COUNTRY_CODES = {
    "CU", #Cuba
    "IR", #Iran
    "KP", #Korea
    "SY", #Syria
}

def rule(event):
    # Return True to match the log event and trigger an alert.
    if deep_get(event, 'p_enrichment', 'ipinfo_location',  'RemoteAddressIP4', 'country') in EMBARGO_COUNTRY_CODES:
        return True
    return False

def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will act as deduplication string.
    return f"Connection made to embargoed country: {deep_get(event, 'p_enrichment', 'ipinfo_location',  'RemoteAddressIP4', 'country')}"

def alert_context(event):
    return crowdstrike_detection_alert_context