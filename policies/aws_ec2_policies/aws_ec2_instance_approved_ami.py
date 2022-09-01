# Tags: ['AWS Managed Rules - Compute']
APPROVED_AMIS = {
    "EXAMPLE-AMI-ID",
}


def policy(resource):
    return resource["ImageId"] in APPROVED_AMIS
