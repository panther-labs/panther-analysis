def rule(_):
    return True


def title(event):
    return f"{event.get('p_source_label', '<UNKNOWN SOURCE>')}: Suspicious Application Session"


def dedup(event):
    return "-".join((
        event.get("client_application" "<UNKNOWN APP>"),
        event.get("client_os" "<UNKNOWN OS>"),
        event.get("client_os_version" "<UNKNOWN VERSION>")
    ))