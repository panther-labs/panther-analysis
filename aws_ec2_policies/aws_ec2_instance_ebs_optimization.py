OPTIMIZABLE_TYPES = {
    "c1.xlarge",
    "c3.xlarge",
    "c3.2xlarge",
    "c3.4xlarge",
    "g2.2xlarge",
    "i2.xlarge",
    "i2.2xlarge",
    "i2.4xlarge",
    "m1.large",
    "m1.xlarge",
    "m2.2xlarge",
    "m2.4xlarge",
    "m3.xlarge",
    "m3.2xlarge",
    "r3.xlarge",
    "r3.2xlarge",
    "r3.4xlarge",
}


def policy(resource):
    # Check if this Instance's instance type can be EBS optimized
    if resource["InstanceType"] not in OPTIMIZABLE_TYPES:
        return True

    # Explicit check for True to avoid returning NoneType
    return resource["EbsOptimized"] is True
