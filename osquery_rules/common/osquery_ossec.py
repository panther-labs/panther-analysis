def rule(event):
    return 'ossec-rootkit' in event['name'] and event['action'] == 'added'
