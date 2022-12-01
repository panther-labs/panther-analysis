from panther_base_helpers import deep_get, aws_rule_context

def rule(event):
    mfa_used = deep_get(event,"additionalEventData","MFAUsed")
    console_login = deep_get(event,"responseElements","ConsoleLogin")

    if mfa_used == "Yes" and console_login == "Failure":
        return True
    return False

def title(event):
    return f'Failed MFA login from {deep_get(event,"userIdentity", "userName")}'

def alert_context(event):
    return aws_rule_context(event)

