import json

def deserialize_administrator_log_event_description(event: dict) -> dict:
    try:
        return json.loads(event["description"])
    except:
        return {}