def rule(event):
    return (event['name'] == 'pack_incident-response_listening_ports' and
            event['columns']['port'] == '22' and event['action'] == 'added')
