from global_filter_auth0 import filter_include_event
from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event
from panther_base_helpers import deep_get

def rule(event):
    description = deep_get(event, "data", "description",default="<NO_DESCRIPTION_FOUND>")
    return description == "Email domain is prohibited and Dangerous"

def title(event):
    user = deep_get(event, "data", "user_name", default="<NO_USER_FOUND>")
    
    return f'Auth0 {user} attempting to login is on restricted list'

# def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # return ''

# def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the alert sent to the SNS/SQS/Webhook destination
    user = deep_get(event, "data", "user_name", default="<NO_USER_FOUND>")
    description = deep_get(event, "data", "description",default="<NO_DESCRIPTION_FOUND>")

    alertcontext = {"description": description, "username": user}
    return alertcontext