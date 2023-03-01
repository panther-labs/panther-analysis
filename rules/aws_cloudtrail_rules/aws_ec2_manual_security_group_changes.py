from panther_base_helpers import aws_rule_context, deep_get, pattern_match_list
from panther_default import aws_cloudtrail_success

PROD_ACCOUNT_IDS = {"11111111111111", "112233445566"}
SG_CHANGE_EVENTS = {
    "CreateSecurityGroup": {
        "fields": ["groupName", "vpcId"],
        "title": "New security group [{groupName}] created by {actor}",
    },
    "AuthorizeSecurityGroupIngress": {
        "fields": ["groupId"],
        "title": "User {actor} has updated security group [{groupId}]",
    },
    "AuthorizeSecurityGroupEgress": {
        "fields": ["groupId"],
        "title": "User {actor} has updated security group [{groupId}]",
    },
}
ALLOWED_USER_AGENTS = {
    "* HashiCorp/?.0 Terraform/*",
    # 'console.ec2.amazonaws.com',
    # 'cloudformation.amazonaws.com',
}
ALLOWED_ROLE_NAMES = {
    "Operator",
    "ContinousDeployment",
}


def rule(event):
    return aws_cloudtrail_success(event) and (
        event.get("eventName") in SG_CHANGE_EVENTS.keys()
        and event.get("recipientAccountId") in PROD_ACCOUNT_IDS
        and
        # Validate the deployment mechanism (Console, CloudFormation, or Terraform)
        not (
            pattern_match_list(event.get("userAgent"), ALLOWED_USER_AGENTS)
            and
            # Validate the IAM Role used is in our acceptable list
            any(role in deep_get(event, "userIdentity", "arn") for role in ALLOWED_ROLE_NAMES)
        )
    )


def dedup(event):
    return ":".join(
        deep_get(event, "requestParameters", field, default="<UNKNOWN_FIELD>")
        for field in SG_CHANGE_EVENTS[event.get("eventName")]["fields"]
    )


def title(event):
    title_fields = {
        field: deep_get(event, "requestParameters", field, default="<UNKNOWN_FIELD>")
        for field in SG_CHANGE_EVENTS[event.get("eventName")]["fields"]
    }
    user = deep_get(event, "userIdentity", "arn", default="<UNKNOWN_USER>").split("/")[-1]
    title_template = SG_CHANGE_EVENTS[event.get("eventName")]["title"]
    title_fields["actor"] = user
    return title_template.format(**title_fields)


def alert_context(event):
    return aws_rule_context(event)
