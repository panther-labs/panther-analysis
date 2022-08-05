def rule(_):
    return True

def title(event):
    action = "".join(event.get("query_text", "").split(" ")[0:2])
    return f"User [{event.get('user_name','<UNKNOWN_ADMIN>')}] performing privileged action [{action}]"
 
