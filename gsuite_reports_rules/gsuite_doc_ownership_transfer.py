from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import gsuite_parameter_lookup as param_lookup

ORG_DOMAINS = {
    '@example.com',
}


def rule(event):
    if event['id'].get('applicationName') != 'admin':
        return False

    details = details_lookup('DOCS_SETTINGS', ['TRANSFER_DOCUMENT_OWNERSHIP'],
                             event)
    if bool(details):
        new_owner = param_lookup(details.get('parameters', {}), 'NEW_VALUE')
        return bool(new_owner) and not any(
            new_owner.endswith(x) for x in ORG_DOMAINS)
    return False
