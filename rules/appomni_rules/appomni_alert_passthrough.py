from panther_base_helpers import deep_get

def rule(event):
    # Only alert where event.kind == "alert"
    if deep_get(event, "event", "kind") == "alert":
        return True
    return False

def title(event):    
    # Create title that includes severity and message
    sev_dict = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}
    sev = sev_dict[deep_get(event, "event", "severity")]
    
    # Use type service in title if only one field, label as 'Multiple Services' if more than one. 
    if len(deep_get(event, "related", "services", "type")) == 1:
        service = deep_get(event, "related", "services", "type")[0]
    else:
        service = "Multiple Services"

    return f'[{sev}] - {service} - {event.get("message")}'

def severity(event):
    # Update Panther alert severity based on severity from AppOmni Alert
    sev = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "Informational"}
    return sev[deep_get(event, "event", "severity")] 

def dedup(event):
    # Use the unique EventID for this alert to make sure we alert each time a new AppOmni alert is logged
    return f'Event ID: {deep_get(event, "appomni", "event", "id")}'

def alert_context(event):
    # Return a dictionary with threat and related data to be included in the alert sent to the alert destination
    return { "threat": deep_get(event, "rule", "threat"),
             "related": deep_get(event, "related")
           }