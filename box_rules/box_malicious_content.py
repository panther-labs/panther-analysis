def rule(event):
    # enterprise events alerts on malicious files
    if event.get('event_type') == 'FILE_MARKED_MALICIOUS':
        return True
    # Box Shield will also alert on malicious content
    if event.get('event_type') != 'SHIELD_ALERT':
        return False
    alert_details = event.get('additional_details', {}).get('shield_alert', {})
    if alert_details.get('rule_category', '') == 'Malicious Content':
        if alert_details.get('risk_score', 0) > 50:
            return True
    return False


def title(event):
    if event.get('event_type') == 'FILE_MARKED_MALICIOUS':
        return 'File [{}], owned by [{}], was marked malicious.'.format(
            event.get('source', {}).get('item_name', "<UNKNOWN_FILE>"),
            event.get('source', {}).get('owned_by',
                                        {}).get('login', '<UNKNOWN_USER>'))

    alert_details = event.get('additional_details', {}).get('shield_alert', {})
    return 'File [{}], owned by [{}], was marked malicious.'.format(
        alert_details.get('alert_summary',
                          {}).get('upload_activity',
                                  {}).get('item_name', '<UNKNOWN_FILE_NAME>'),
        alert_details.get('user', {}).get('email', '<UNKNOWN_USER>'))
