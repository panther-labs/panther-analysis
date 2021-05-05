def rule(event):
    return 4.0 <= float(event.get("severity", 0)) <= 6.9


def dedup(event):
    return event.get("id")


def title(event):
    return event.get("title")
