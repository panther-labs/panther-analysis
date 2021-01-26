from panther_base_helpers import box_parse_additional_details, deep_get


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
    description = deep_get(details, 'shield_alert', 'alert_summary', 'description')

    if description:
        return description
    return 'Anamalous download activity triggered by user [{}].'.format(
        deep_get(event, 'created_by', 'name', default='<UNKNOWN_USER>'))
