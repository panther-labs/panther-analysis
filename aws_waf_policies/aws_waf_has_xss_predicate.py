from panther_base_helpers import IN_PCI_SCOPE, deep_get


def policy(resource):
    if not IN_PCI_SCOPE(resource):
        return True

    for rule in resource["Rules"] or []:
        # Must block the XSS
        if deep_get(rule, "Action", "Type") != "BLOCK":
            continue

        # Only passes if there is an XSS matching predicate
        for predicate in rule["Predicates"]:
            if predicate["Type"] == "XssMatch":
                return True

    return False
