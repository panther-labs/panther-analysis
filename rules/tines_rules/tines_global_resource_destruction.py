def rule(event):
    return event.get('operation_name') == 'GlobalResourceDestruction'

def title(event):
    user = event.get('user_email')
    tines_instance = event.get('p_source_label')
    return f"Tines Global Resource Destruction by {user} on {tines_instance}"