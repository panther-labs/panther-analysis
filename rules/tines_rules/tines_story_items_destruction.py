from panther_base_helpers import deep_get
from panther_tines_helpers import tines_alert_context

def rule(event):
    return event.get('operation_name') == 'StoryItemsDestruction'

def title(event):
    operation = deep_get(event, 'operation_name', default='Unknown Operation')
    user = deep_get(event, 'user_email', default='Unknown User')
    tines_instance = deep_get(event, 'p_source_label', default='Unknown Tines Instance')
    return f"Tines [{operation}] by [{user}] on [{tines_instance}]"

def alert_context(event):
    return tines_alert_context(event)