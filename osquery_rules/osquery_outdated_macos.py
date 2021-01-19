from panther_base_helpers import deep_get

SUPPORTED_VERSIONS = [
    '10.15.1',
    '10.15.2',
    '10.15.3',
]


def rule(event):
    return (event['name'] == 'pack_vuln-management_os_version' and
            deep_get(event, 'columns', 'platform') == 'darwin' and
            deep_get(event, 'columns', 'version') not in SUPPORTED_VERSIONS and
            event['action'] == 'added')
