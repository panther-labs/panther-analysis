def rule(event):
    return (event['name'] == 'pack/mac-cis/SoftwareUpdate' and
            event['action'] == 'added' and
            event['columns'].get('domain') == 'com.apple.SoftwareUpdate' and
            event['columns'].get('key') == 'AutomaticCheckEnabled' and
            # Send an alert if not set to "true"
            not bool(event['columns'].get('value')))
