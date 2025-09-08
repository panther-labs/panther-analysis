import json


# 'additional_details' from box logs varies by event_type.
# This helper wraps the process of extracting those details.
def box_parse_additional_details(event):
    additional_details = event.get("additional_details", {})
    if isinstance(additional_details, (str, bytes)):
        try:
            return json.loads(additional_details)
        except ValueError:
            return {}
    return additional_details
