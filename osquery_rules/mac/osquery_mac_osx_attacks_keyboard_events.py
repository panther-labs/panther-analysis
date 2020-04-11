from fnmatch import fnmatch

# sip protects against writing malware into the paths below.
# additional apps can be added to this list based on your environments.
#
# more info: https://support.apple.com/en-us/HT204899
APPROVED_PROCESS_PATHS = {
    '/System/*',
    '/usr/*',
    '/bin/*',
    '/sbin/*',
    '/var/*',
}

QUERIES = {
    'pack_osx-attacks_Keyboard_Event_Taps',
    'pack/osx-attacks/Keyboard_Event_Taps'
}


def rule(event):
    if event['name'] not in QUERIES:
        return False

    if event['action'] != 'added':
        return False

    process_path = event['columns'].get('path')
    if not process_path:
        return False

    # Alert if the process is running outside any of the approved paths
    # TODO: Convert this fnmatch pattern below to a helper
    return not any([fnmatch(process_path, p) for p in APPROVED_PROCESS_PATHS])


def dedup(event):
    return event.get('hostIdentifier')


def title(event):
    return 'Keylogger malware detected on {}'.format(
        event.get('hostIdentifier'))
