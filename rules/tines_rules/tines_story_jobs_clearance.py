def rule(event):
    return event.get('operation_name') == 'StoryJobsClearance'

def title(event):
    operation = event.get('operation_name')
    user = event.get('user_email')
    tines_instance = event.get('p_source_label')
    return f"Tines {operation} by {user} on {tines_instance}"