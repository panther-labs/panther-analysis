from panther_base_helpers import deep_get


def policy(resource):
    # per https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-status.html
    # > 16 Instance.State values indicate shutdown
    if deep_get(resource, "State", "Code", default=0) > 16:
        return True
    return deep_get(resource, "Monitoring", "State") != "disabled"
