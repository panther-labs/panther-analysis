def rule(event):
    return ('SoftwareUpdate' in event['name'] and event['action'] == 'added' and
            event['columns'].get('domain') == 'com.apple.SoftwareUpdate' and
            event['columns'].get('key') == 'AutomaticCheckEnabled' and
            # Send an alert if not set to "true"
            event['columns'].get('value') == 'false')
