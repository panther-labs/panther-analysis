from panther_base_helpers import deep_walk


def rule(event):
    data_values = deep_walk(event, "supporting_data", "data_values")
    if data_values and data_values[0] == 403:
        return True
    return False


def title(event):
    user = event.get("user", "<USER_NOT_FOUND>")
    return f"Many unauthorized API calls from user [{user}]"
