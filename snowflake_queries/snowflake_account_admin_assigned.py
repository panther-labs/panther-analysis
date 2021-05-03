def rule(_):
    return True

def title(event):
    target = " ".join(event.get("query_text","").split(" ")[-2:])
    return f"Snowflake AccountAdmin granted to {target}"
