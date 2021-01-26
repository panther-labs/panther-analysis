from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup
from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, 'id', 'applicationName') != 'rules':
        return False

    details = details_lookup('rule_trigger_type', ['rule_trigger'], event)
    return bool(details) and param_lookup(details.get('parameters', {}),
                                          'severity') == 'LOW'
