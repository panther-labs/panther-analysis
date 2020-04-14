def rule(event):
    return 0.1 <= float(event.get('severity', 0)) <= 3.9


def dedup(event):
    return event.get('id')


def title(event):
    return event.get('title')
