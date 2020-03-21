# Tags: ['AWS Managed Rules - Compute']
# This is a list of approved VPC IDs. All EC2 instances must exist in one of these VPCs.
APPROVED_VPCS = {
    'EXAMPLE-VPC-ID',
}

# IGNORED_INSTANCE_TAGS is to describe tags that, if present on an EC2 instance, indicate that the
# instance is to be exempted from this rule.
# Example: IGNORED_INSTANCE_TAGS = {'KeyOne': 'ValueOne', 'KeyTwo': 'ValueTwo'}
IGNORED_INSTANCE_TAGS = {
    '\\KeyOne': '\\ValueOne',
}


def policy(resource):
    # Check if any tags on this EC2 instance make it exempt from this rule
    if resource['Tags'] is not None:
        tag_presence = [
            tag['Key'] in IGNORED_INSTANCE_TAGS and
            tag['Value'] == IGNORED_INSTANCE_TAGS[tag['Key']]
            for tag in resource['Tags']
        ]
        if any(tag_presence):
            return True

    return resource['VpcId'] in APPROVED_VPCS
