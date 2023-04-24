from panther_base_helpers import crowdstrike_detection_alert_context
import re

def rule(event):
    # Return True to match the log event and trigger an alert.
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{10,}[=]{0,2}\.')

    if  base64_pattern.search(event.get('query_name', default=''), re.IGNORECASE):   
        return True
    else:
        return False

def title(event):
    defang_query = event.get("query_name").replace(".", "[.]")
    return f'Base64 encoded query detected from {event.get("srcaddr")}, [{defang_query}]'

def dedup(event):
    return f'{event.get("aid")}'

def alert_context(event):
    return crowdstrike_detection_alert_context