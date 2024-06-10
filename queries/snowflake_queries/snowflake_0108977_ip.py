def rule(_):
    return True


def title(event):
    client_ip = event.get("client_ip", "<NO_IP_FOUND>")
    user_name = event.get("user_name", "<NO USERNAME FOUND>")
    return f"{user_name} accessed Snowflake from {client_ip}"
