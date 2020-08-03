from panther_base_helpers import gsuite_parameter_lookup as param_lookup


def rule(event):
    if event['id'].get('applicationName') != 'rules':
        return False

    for details in event.get('events', [{}]):
        if (details.get('type') == 'rule_trigger_type' and
                details.get('name') == 'rule_trigger' and param_lookup(
                    details.get('parameters', {}), 'severity') == 'LOW'):
            return True

    return False
