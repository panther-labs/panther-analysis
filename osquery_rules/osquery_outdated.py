LATEST_VERSION = '4.2.0'


def rule(event):
    return (event['name'] == 'pack_it-compliance_osquery_info' and
            event['columns']['version'] != LATEST_VERSION and
            event['action'] == 'added')


def title(event):
    return 'Osquery Version {} is Outdated'.format(
        event['columns'].get('version'))
