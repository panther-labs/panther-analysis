def rule(_):
    return True

def title(event):
    return f"User {event.get('name')} logged in with Password instead of RSA key"
 
