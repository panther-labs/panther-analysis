from fnmatch import fnmatch
from panther_base_helpers import deep_get

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

APPROVED_APPLICATION_NAMES = {'Adobe Photoshop CC 2019'}


def rule(event):
    if 'Keyboard_Event_Taps' not in event.get('name', ''):
        return False

    if event.get('action') != 'added':
        return False

    process_path = deep_get(event, 'columns', 'path', default='')
    if process_path == '':
        return False

    if deep_get(event, 'columns', 'name') in APPROVED_APPLICATION_NAMES:
        return False

    # Alert if the process is running outside any of the approved paths
    # TODO: Convert this fnmatch pattern below to a helper
    return not any([fnmatch(process_path, p) for p in APPROVED_PROCESS_PATHS])


def title(event):
    return 'Keylogger malware detected on [{}]'.format(
        event.get('hostIdentifier'))
