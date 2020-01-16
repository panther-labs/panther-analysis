# ORDERING is a dictionary that describes the required ordering of Web ACL rules for a
# given web acl ID. Map the Web ACL ID to an ordered tuple of Web ACL rule IDs
# Example usage:
# ORDERING{
#   'WebAclId-123': ('FirstRuleId', 'SecondRuleId', 'ThirdRuleId'),
# }
ORDERING = {
    'EXAMPLE_WEB_ACL_ID': ('EXAMPLE_RULE_1_ID', 'EXAMPLE_RULE_2_ID'),
}


def policy(resource):
    # Check if Web ACL rule ordering is being enforced
    if resource['WebACLId'] not in ORDERING:
        return True
    web_acl_rules = resource['Rules']

    # Check that the Web ACL has the correct number of rules
    if len(ORDERING[resource['WebACLId']]) != len(web_acl_rules):
        return False

    # Confirm that each rule is ordered correctly
    for web_acl_rule in web_acl_rules:
        # Rules are not neccessarily listed in their priority order in the rules list.
        # This determines their priority order, and offsets by one to be indexed starting at 0.
        priority_order = web_acl_rule['Priority'] - 1
        if web_acl_rule['RuleId'] != ORDERING[resource['WebACLId']][priority_order]:
            return False

    # The rules all matched correctly, return True
    return True
