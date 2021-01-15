from panther_base_helpers import box_parse_additional_details


def rule(event):
    if event.get('event_type') != 'SHIELD_ALERT':
        return False
    alert_details = box_parse_additional_details(event).get('shield_alert', {})
    if alert_details.get('rule_category', '') == 'Anomalous Download':
        if alert_details.get('risk_score', 0) > 50:
            return True
    return False


def title(event):
    details = box_parse_additional_details(event)
    description = details.get('shield_alert',
                              {}).get('alert_summary',
                                      {}).get('description', '')
    if description:
        return description
    return 'Anamalous download activity triggered by user [{}].'.format(
        event.get('created_by', {}).get('name', '<UNKNOWN_USER>'))
