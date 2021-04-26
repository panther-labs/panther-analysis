def rule(_):
    return True

def title(event):
    username = ''.join(event.get('query_text', '').split(' ')[2])
    return f"Snowflake user [{username}] enabled by [{event.get('user_name','<UNKNOWN_ADMIN>')}]"
