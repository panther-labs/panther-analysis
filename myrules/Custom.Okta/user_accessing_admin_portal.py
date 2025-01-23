from panther_okta_helpers import okta_alert_context

def rule(event):
    return deep_get(event, "debugContext", "displayMessage", default="NO DISPLAY MESSAGE") == "User aaccessing Okta admin app"
    
def title(event):
    user = deep_get(event, "actor", default="NO USER FOUND")
    return f'{user} is accessing the Okta admin app'
    
def alert_context(event):
    return okta_alert_context(event)