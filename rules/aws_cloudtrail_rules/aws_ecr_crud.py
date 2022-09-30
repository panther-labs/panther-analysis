from panther_base_helpers import aws_rule_context, deep_get

ECR_CRUD_EVENTS = {
    'BatchCheckLayerAvailability',
    'BatchDeleteImage',
    'BatchGetImage',
    'CompleteLayerUpload',
    'CreateRepository',
    'DeleteRepository',
    'DeleteRepositoryPolicy',
    'DescribeImages',
    'DescribeRepositories',
    'GetAuthorizationToken',
    'GetDownloadUrlForLayer',
    'GetRepositoryPolicy',
    'InitiateLayerUpload',
    'ListImages',
    'PutImage',
    'SetRepositoryPolicy',
    'UploadLayerPart'
}

EXPECTED_AWS_ACCOUNTS_AND_REGIONS = {
    "123456789012": {
        "us-west-1",
        "us-west-2"
    },
    "103456789012": {
        "us-east-1",
        "us-east-2"
    }
}

def rule(event):
    if event.get("eventSource") == "ecr.amazonaws.com" and \
        event.get("eventName") in ECR_CRUD_EVENTS:
        aws_account_id = deep_get(event, "userIdentity", "accountId")
        if aws_account_id in EXPECTED_AWS_ACCOUNTS_AND_REGIONS:
            if event.get("awsRegion") not in EXPECTED_AWS_ACCOUNTS_AND_REGIONS.get(aws_account_id):
                return True
        else:
            return True
    return False


def dedup(event):
    return event.get("recipientAccountId")


def alert_context(event):
    return aws_rule_context(event)
