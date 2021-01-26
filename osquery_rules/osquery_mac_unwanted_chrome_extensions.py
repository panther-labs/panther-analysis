def rule(event):
    return ('unwanted-chrome-extensions' in event.get('name') and
            event.get('action') == 'added')


def title(event):
    return 'Unwanted Chrome extension(s) detected on [{}]'.format(
        event.get('hostIdentifier'))
