# MAPPINGS is a dictionary where the Key is an application load balancer ARN, and the
# Value is a WAF web ACL ID. For each Load Balancer ARN present in MAPPINGS,
# this rule verifies that the load balancer has the associated Web ACL
MAPPINGS = {
    "TEST_LOAD_BALANCER_ARN": "TEST_WAF_WEB_ACL_ID",
}


def policy(resource):
    # Check if a Web ACL is required for this load balancer
    if resource['LoadBalancerArn'] not in MAPPINGS:
        return True

    # Check if a Web ACL exists for this load balancer
    if resource['WebAcl'] is None:
        return False

    # Check that the correct Web ACL is assigned for this load balancer
    return resource['WebAcl']['WebACLId'] == MAPPINGS[
        resource['LoadBalancerArn']]
