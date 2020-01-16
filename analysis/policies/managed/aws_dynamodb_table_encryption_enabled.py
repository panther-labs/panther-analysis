def policy(resource):
    return (
        resource['SSEDescription'] is not None and resource['SSEDescription']['Status'] == 'ENABLED'
    )
