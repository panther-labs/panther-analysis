def rule(_):
    return True

def title(event):
    query_text = event.get('query_text', '').split(' ')
    if len(query_text) > 2:
        return f"Snowflake user [{query_text[2]}] enabled by [{event.get('user_name','<UNKNOWN_ADMIN>')}]"
    return f"Snowflake user [<UNKNOWN_USER>] enabled by [{event.get('user_name','<UNKNOWN_ADMIN>')}]"
 
