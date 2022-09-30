from panther_base_helpers import aws_rule_context, deep_get
import pdb

LAMBDA_CRUD_EVENTS = {
    'AddPermission',
    'CreateAlias',
    'CreateEventSourceMapping',
    'CreateFunction',
    'DeleteAlias',
    'DeleteEventSourceMapping',
    'DeleteFunction',
    'GetAlias',
    'GetEventSourceMapping',
    'GetFunction',
    'GetFunctionConfiguration',
    'GetPolicy',
    'InvokeFunction',
    'InvokeAsync',
    'ListAliases',
    'ListEventSourceMappings',
    'ListFunctions',
    'ListVersionsByFunction',
    'PublishVersion',
    'RemovePermission',
    'UpdateAlias',
    'UpdateEventSourceMapping',
    'UpdateFunctionCode',
    'UpdateFunctionConfiguration'
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
    if event.get("eventSource") == "lambda.amazonaws.com":
        if event.get("eventName") in LAMBDA_CRUD_EVENTS:
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