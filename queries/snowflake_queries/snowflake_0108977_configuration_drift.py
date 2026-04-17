def rule(_):
    return True


def title(event):
    user_name = event.get("user_name", "<NO USERNAME FOUND>")
    action = event.get("query_text", "<NO QUERY FOUND>").split(" ")[:2]
    target = " ".join(event.get("query_text", "").split(" ")[-2:])
    return f"{user_name} performed {action} on {target}"
