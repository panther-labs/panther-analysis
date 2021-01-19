from panther_base_helpers import deep_get


def rule(event):
    return (event['name'] == 'pack_incident-response_listening_ports' and
            deep_get(event, 'columns', 'port') == '22' and
            event['action'] == 'added')
