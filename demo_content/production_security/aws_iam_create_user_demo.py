from panther_aws_helpers import aws_cloudtrail_success


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") == "CreateUser"


def title(event):
    actor_arn = event.deep_get("userIdentity", "arn", default="")
    target_user = event.deep_get("requestParameters", "userName", default="")

    # Extract meaningful actor name from ARN
    if ":assumed-role/" in actor_arn:
        # For assumed roles, get the role name and user
        role_part = actor_arn.split(":assumed-role/")[1]
        if "/" in role_part:
            role_name, session_name = role_part.split("/", 1)
            actor_display = f"assumed role {role_name} (session: {session_name})"
        else:
            actor_display = f"assumed role {role_part}"
    elif ":user/" in actor_arn:
        user_name = actor_arn.split(":user/")[1]
        actor_display = f"user {user_name}"
    elif ":root" in actor_arn:
        actor_display = "root account"
    else:
        actor_display = actor_arn

    return f"IAM user [{target_user}] created by [{actor_display}]"


def runbook(event):
    return f"""
    Identify who created the IAM user ({event.get("requestParameters", {}).get("userName", "")}). 
    
    Check for suspicious follow-up activities, like admin policy attachments or access key creation within 1 hour of ({event.get("eventTime", "")}) in the aws_cloudtrail table.

    If unauthorized, immediately disable the user and investigate any actions taken using CloudTrail logs.
    """


def alert_context(event):
    context = {
        "target": event.deep_get("requestParameters", "userName", default=""),
        "actor": event.deep_get("userIdentity", "arn", default=""),
        "timestamp": event.get("eventTime", ""),
        "parameters": event.deep_get("requestParameters", default={}),
        "action": event.get("eventName", ""),
    }
    return context
