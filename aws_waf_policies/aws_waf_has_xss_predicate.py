from panther_base_helpers import IN_PCI_SCOPE  # pylint: disable=import-error


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    for rule in resource['Rules'] or []:
        # Must block the XSS
        if rule['Action']['Type'] != 'BLOCK':
            continue

        # Only passes if there is an XSS matching predicate
        for predicate in rule['Predicates']:
            if predicate['Type'] == 'XssMatch':
                return True

    return False
