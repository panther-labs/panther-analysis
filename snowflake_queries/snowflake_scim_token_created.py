def rule(_):
    return True

def title(event):
    return f"A SCIM access token was created by user {event.get('user_name')}."
 
