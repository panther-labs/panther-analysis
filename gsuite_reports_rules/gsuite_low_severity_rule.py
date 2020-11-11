from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup


def rule(event):
    if event['id'].get('applicationName') != 'rules':
        return False

    details = details_lookup('rule_trigger_type', ['rule_trigger'], event)
    return bool(details) and param_lookup(details.get('parameters', {}),
                                          'severity') == 'LOW'
