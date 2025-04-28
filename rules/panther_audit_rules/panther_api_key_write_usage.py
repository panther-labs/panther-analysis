# List of write-based actions that we want to monitor when performed with API keys
WRITE_BASED_ACTIONS = [
    # Detection Operations
    "CREATE_DETECTION",
    "UPDATE_DETECTION",
    "DELETE_DETECTION",
    "UPDATE_DETECTION_STATE",
    
    # Data Model Operations
    "CREATE_DATA_MODEL",
    "UPDATE_DATA_MODEL",
    "DELETE_DATA_MODEL",
    
    # Global Helper Operations
    "CREATE_GLOBAL_HELPER",
    "UPDATE_GLOBAL_HELPER",
    "DELETE_GLOBAL_HELPER",
    
    # User & Role Operations
    "CREATE_USER_ROLE",
    "UPDATE_USER_ROLE",
    "DELETE_USER_ROLE",
    "UPDATE_USER",
    "DELETE_USER",
    
    # System Settings
    "UPDATE_SAML_SETTINGS",
    "UPDATE_GENERAL_SETTINGS",
    
    # API Token Management
    "DELETE_API_TOKEN",
    "UPDATE_API_TOKEN",
    
    # Log Source Management
    "DELETE_LOG_SOURCE",
    "UPDATE_LOG_SOURCE",
    
    # Alert & Notification Management
    "UPDATE_ALERT_DESTINATION",
    "UPDATE_NOTIFICATION",
    
    # Policy & Rule Management
    "UPDATE_POLICY",
    "UPDATE_RULE_AND_FILTER",
    
    # Data Lake & Dashboard Operations
    "UPDATE_SAVED_DATA_LAKE_QUERY",
    "UPDATE_DASHBOARD"
]

def rule(event):
    # Check if the action is a write operation and was successful
    if event.get("actionName") not in WRITE_BASED_ACTIONS:
        return False
    if event.get("actionResult") != "SUCCEEDED":
        return False
    
    return event.deep_get("actor", "type") == "TOKEN"

def title(event):
    return f"Write operation performed using API key '{event.deep_get('actor', 'name')}'"

def alert_context(event):
    return {
        "action_name": event.get("actionName"),
        "action_description": event.get("actionDescription"),
        "token_name": event.deep_get("actor", "name"),
        "token_id": event.deep_get("actor", "id"),
        "ip": event.udm("source_ip"),
        "action_params": event.get("actionParams")
    }

def severity(event):
    # Higher severity for security-critical operations
    high_risk_actions = {
        "UPDATE_SAML_SETTINGS",
        "UPDATE_GENERAL_SETTINGS",
        "CREATE_USER_ROLE",
        "UPDATE_USER_ROLE",
        "UPDATE_USER",
        "DELETE_USER",
        "DELETE_API_TOKEN",
        "UPDATE_API_TOKEN",
        "UPDATE_ALERT_DESTINATION"
    }
    
    if event.get("actionName") in high_risk_actions:
        return "HIGH"
    return "MEDIUM" 
