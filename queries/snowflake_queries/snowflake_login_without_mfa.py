MFA_EXCEPTIONS = {
    "PANTHER_READONLY",
    "PANTHER_ADMIN"
}

def rule(event):
    return event.get("user_name", "") not in MFA_EXCEPTIONS
 
