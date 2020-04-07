def rule(event):
    return 'unwanted-chrome-extensions' in event['name'] and event[
        'action'] == 'added'


def dedup(event):
    return event['columns'].get('user')
