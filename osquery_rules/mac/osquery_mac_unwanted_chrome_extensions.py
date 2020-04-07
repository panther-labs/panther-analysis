def rule(event):
    return ('unwanted-chrome-extensions' in event['name'] and
            event['action'] == 'added')


def dedup(event):
    return event.get('hostIdentifier')


def title(event):
    return 'Unwanted chrome extension(s) detected on {}'.format(
        event['hostIdentifier'])
