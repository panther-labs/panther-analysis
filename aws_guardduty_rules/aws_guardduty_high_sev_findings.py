def rule(event):
    return 7.0 <= float(event.get("severity", 0)) <= 8.9


def dedup(event):
    return event.get("id")


def title(event):
    return event.get("title")
