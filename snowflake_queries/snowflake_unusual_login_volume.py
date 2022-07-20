def rule(_):
    return True

def title(event):
    return f"{event.get('user_name')} has exceeded the normal amount of Snowflake logins"
 
