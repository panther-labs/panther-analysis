def rule(_):
    return True


def title(event):
    query_id = event.get("query_id", "<NO QUERY ID FOUND>")
    role_name = event.get("role_name", "<NO ROLE NAME FOUND>")
    user_name = event.get("user_name", "<NO USER NAME FOUND>")
    return f"{user_name} with role {role_name} performed query {query_id}"
