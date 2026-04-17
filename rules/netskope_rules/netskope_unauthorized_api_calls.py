def rule(event):
    data_values = event.deep_walk("supporting_data", "data_values")
    if data_values and data_values[0] == 403:
        return True
    return False


def title(event):
    user = event.get("user", "<USER_NOT_FOUND>")
    return f"Many unauthorized API calls from user [{user}]"
