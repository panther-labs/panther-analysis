from panther_base_helpers import box_parse_additional_details

SUSPICIOUS_EVENT_TYPES = [
    'Suspicious Locations',
    'Suspicious Sessions',
]


def rule(event):
    if event.get('event_type') != 'SHIELD_ALERT':
        return False
    alert_details = box_parse_additional_details(event).get('shield_alert', {})
    if alert_details.get('rule_category', '') in SUSPICIOUS_EVENT_TYPES:
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
    return 'Shield medium to high risk, suspicious event alert triggered for user [{}]'.format(
        details.get('shield_alert', {}).get('user', {}).get('email'))
