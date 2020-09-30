def rule(event):
    return ('unwanted-chrome-extensions' in event['name'] and
            event['action'] == 'added')


def title(event):
    return 'Unwanted Chrome extension(s) detected on [{}]'.format(
        event['hostIdentifier'])
