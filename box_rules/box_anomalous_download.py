def rule(event):
    if event.get('event_type') != 'SHIELD_ALERT':
        return False
    alert_details = event.get('additional_details', {}).get('shield_alert', {})
    if alert_details.get('rule_category', '') == 'Anomalous Download':
        if alert_details.get('risk_score', 0) > 50:
            return True
    return False


def title(event):
    description = event.get('additional_details',
                            {}).get('shield_alert',
                                    {}).get('alert_summary',
                                            {}).get('description', '')
    if description:
        return description
    return 'Anamalous download activity triggered by user [{}].'.format(
        event.get('created_by', {}).get('name', '<UNKNOWN_USER>'))
