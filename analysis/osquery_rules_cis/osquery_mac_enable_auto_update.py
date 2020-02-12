def rule(event):
    if event.get('domain') != 'com.apple.SoftwareUpdate' or event.get(
            'key') != 'AutomaticCheckEnabled':
        return False

    return not event.get('value')
