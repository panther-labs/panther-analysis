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


def rule(event):
    if not event.get('name', '').startswith('pack_osx-attacks_'):
        return False

    if event.get('action') != 'added':
        return False

    process_path = event.get('columns', {}).get('path')
    # Alert if the process is running outside any of the approved paths
    return not any([fnmatch(process_path, p) for p in APPROVED_PROCESS_PATHS])
