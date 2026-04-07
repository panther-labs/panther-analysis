import base64
import binascii
import os
from typing import Any, Dict, List

import boto3
from panther_base_helpers import deep_get, pantherflow_investigation


class BadLookup(Exception):
    """Error returned when a resource lookup fails."""


class PantherBadInput(Exception):
    """Error returned when a Panther helper function is provided bad input."""


_RESOURCE_TABLE = None  # boto3.Table resource, lazily constructed
FIPS_ENABLED = os.getenv("ENABLE_FIPS", "").lower() == "true"
FIPS_SUFFIX = "-fips." + os.getenv("AWS_REGION", "") + ".amazonaws.com"


def aws_strip_role_session_id(user_identity_arn):
    # The ARN structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split("/")
    if arn_parts:
        return "/".join(arn_parts[:2])
    return user_identity_arn


def aws_rule_context(event):
    return {
        "eventName": event.get("eventName", "<MISSING_EVENT_NAME>"),
        "eventSource": event.get("eventSource", "<MISSING_ACCOUNT_ID>"),
        "awsRegion": event.get("awsRegion", "<MISSING_AWS_REGION>"),
        "recipientAccountId": event.get("recipientAccountId", "<MISSING_ACCOUNT_ID>"),
        "sourceIPAddress": event.get("sourceIPAddress", "<MISSING_SOURCE_IP>"),
        "userAgent": event.get("userAgent", "<MISSING_USER_AGENT>"),
        "userIdentity": event.get("userIdentity", "<MISSING_USER_IDENTITY>"),
        "PantherFlow Investigation": pantherflow_investigation(event),
    }


def aws_rds_context(event):
    context = aws_rule_context(event)
    context["db_identifier"] = event.deep_get(
        "requestParameters", "dBInstanceIdentifier"
    ) or event.deep_get("requestParameters", "dBClusterIdentifier", default="N/A")
    context["db_instance_arn"] = event.deep_get(
        "responseElements", "dBInstanceArn"
    ) or event.deep_get("responseElements", "dBClusterArn", default="N/A")
    return context


def aws_guardduty_context(event):
    return {
        "description": event.get("description", "<MISSING DESCRIPTION>"),
        "severity": event.get("severity", "<MISSING SEVERITY>"),
        "id": event.get("id", "<MISSING ID>"),
        "type": event.get("type", "<MISSING TYPE>"),
        "resource": event.get("resource", {}),
        "service": event.get("service", {}),
        "accountId": event.get("accountId", "<MISSING ACCOUNT ID>"),
    }


def eks_panther_obj_ref(event):
    user = event.deep_get("user", "username", default="<NO_USERNAME>")
    source_ips = event.get("sourceIPs", ["0.0.0.0"])  # nosec
    verb = event.get("verb", "<NO_VERB>")
    obj_name = event.deep_get("objectRef", "name", default="<NO_OBJECT_NAME>")
    obj_ns = event.deep_get("objectRef", "namespace", default="<NO_OBJECT_NAMESPACE>")
    obj_res = event.deep_get("objectRef", "resource", default="<NO_OBJECT_RESOURCE>")
    obj_subres = event.deep_get("objectRef", "subresource", default="")
    p_source_label = event.get("p_source_label", "<NO_P_SOURCE_LABEL>")
    if obj_subres:
        obj_res = "/".join([obj_res, obj_subres])
    return {
        "actor": user,
        "ns": obj_ns,
        "object": obj_name,
        "resource": obj_res,
        "sourceIPs": source_ips,
        "verb": verb,
        "p_source_label": p_source_label,
    }


def aws_cloudtrail_success(event):
    if event.get("errorCode", "") or event.get("errorMessage", ""):
        return False
    return True


def aws_event_tense(event_name):
    """Convert an AWS CloudTrail eventName to be interpolated in alert titles

    An example is passing in StartInstance and returning 'started'.
    This would then be used in an alert title such as
    'The EC2 instance my-instance was started'.

    Args:
        event_name (str): The CloudTrail eventName

    Returns:
        str: A tensed version of the event name
    """
    mapping = {
        "Create": "created",
        "Delete": "deleted",
        "Start": "started",
        "Stop": "stopped",
        "Update": "updated",
    }
    for event_prefix, tensed in mapping.items():
        if event_name.startswith(event_prefix):
            return tensed
    # If the event pattern doesn't exist, return original
    return event_name


# Adapted from https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489
def extract_account_id(uniq_id: str):
    """retrieve the AWS account ID associated with a given unique ID"""
    no_prefix = uniq_id[4:20]  # remove the four-character prefix
    base32_key = base64.b32decode(no_prefix)  # remainder of the key is base32-encoded
    decoded = base32_key[0:6]  # retrieve the 10-byte string

    # Convert the 10-byte string to an integer
    id_int = int.from_bytes(decoded, byteorder="big", signed=False)
    mask = int.from_bytes(binascii.unhexlify(b"7fffffffff80"), byteorder="big", signed=False)

    # Do a bitwise AND with the mask to retrieve the account ID
    # (divide the 10-byte key integer by 128 and remove the fractional part(s))
    account_id = (id_int & mask) >> 7
    return str(account_id)


# backwards compatibility for old aws_key_account_id
def aws_key_account_id(aws_key: str):
    return extract_account_id(aws_key)


def aws_regions() -> List[str]:
    """return a list of AWS regions"""
    return [
        "ap-east-1",
        "ap-northeast-1",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ca-central-1",
        "ca-central-1",
        "eu-central-1",
        "eu-central-1",
        "eu-central-2",
        "eu-north-1",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-1",
        "eu-west-2",
        "eu-west-2",
        "eu-west-3",
        "eu-west-3",
        "il-central-1",
        "me-central-1",
        "me-south-1",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
    ]


def lookup_aws_account_name(account_id):
    """Lookup the AWS account name, return the ID if not found
    Deprecated: this function remains for backwards compatibility
    Args:
        account_id (str): The AWS account ID
    Returns:
        str: The AWS account ID
    """
    return account_id


def get_s3_arn_by_name(name: str) -> str:
    """This function is used to construct an s3 bucket ARN from its name."""
    if name == "":
        raise PantherBadInput("s3 name cannot be blank")
    return "arn:aws:s3:::" + name


def s3_lookup_by_name(name: str) -> Dict[str, Any]:
    """This function is used to get an S3 bucket resource from just its name."""
    return resource_lookup(get_s3_arn_by_name(name))


def resource_table() -> boto3.resource:
    """Lazily build resource table"""
    # pylint: disable=global-statement
    global _RESOURCE_TABLE
    if not _RESOURCE_TABLE:
        # pylint: disable=no-member
        _RESOURCE_TABLE = boto3.resource(
            "dynamodb",
            endpoint_url="https://dynamodb" + FIPS_SUFFIX if FIPS_ENABLED else None,
        ).Table("panther-resources")
    return _RESOURCE_TABLE


def resource_lookup(resource_id: str) -> Dict[str, Any]:
    """This function is used to get a resource from the resources-api based on its resourceID."""
    # Validate input so we can provide meaningful error messages to users
    if resource_id == "":
        raise PantherBadInput("resourceId cannot be blank")

    # Get the item from dynamo
    response = resource_table().get_item(Key={"id": resource_id})

    # Check if dynamo failed
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code != 200:
        raise BadLookup("dynamodb - " + str(status_code) + " HTTPStatusCode")

    # Check if the item was found
    if "Item" not in response:
        raise BadLookup(resource_id + " not found")

    # Return just the attributes of the item
    return response["Item"]["attributes"]


# get actor user from correct field based on identity type
# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html#cloudtrail-event-reference-user-identity-fields
def get_actor_user(event):
    # IMPORTANT: We can't use event.deep_get here because this function gets called in the UDM
    #   module.
    user_type = deep_get(event, "userIdentity", "type")
    if user_type == "Root":
        actor_user = deep_get(
            event,
            "userIdentity",
            "userName",
            default=deep_get(event, "userIdentity", "accountId", default="UnknownRootUser"),
        )
    elif user_type in ("IAMUser", "Directory", "Unknown", "SAMLUser", "WebIdentityUser"):
        actor_user = deep_get(event, "userIdentity", "userName", default=f"Unknown{user_type}")
    elif user_type in ("AssumedRole", "Role", "FederatedUser"):
        actor_user = deep_get(
            event,
            "userIdentity",
            "sessionContext",
            "sessionIssuer",
            "userName",
            default=f"Unknown{user_type}",
        )
        # If SSO assumed role, the session username is generic, return name from principalId
        if actor_user.startswith("AWSReservedSSO_"):
            actor_user = (
                deep_get(event, "userIdentity", "principalId", default=f"Unknown{user_type}")
            ).split(":")[1]
    elif user_type == "IdentityCenterUser":
        actor_user = deep_get(
            event, "additionalEventData", "UserName", default=f"Unknown{user_type}"
        )
    elif user_type in ("AWSService", "AWSAccount"):
        actor_user = event.get("sourceIdentity", f"Unknown{user_type}")
    elif event.get("eventType") == "AwsServiceEvent":
        actor_user = deep_get(event, "userIdentity", "invokedBy", default="UnknownAwsServiceEvent")
    else:
        actor_user = "UnknownUser"
    return actor_user


# ---- AWS WAF Managed Rule Group Helpers ----


def _waf_normalize_groups(rule_groups):
    """Normalize rule_groups to a list."""
    if isinstance(rule_groups, str):
        return [rule_groups]
    return rule_groups


def _waf_matches_any_group(value, rule_groups):
    """Check if value contains any of the rule group names."""
    return any(group in value for group in rule_groups)


def _waf_rule_group_has_match(group):
    """Check if a ruleGroupList entry has any terminating or non-terminating matches."""
    terminating = group.get("terminatingRule") or {}
    if terminating.get("ruleId"):
        return True
    for match in group.get("nonTerminatingMatchingRules", []) or []:
        if match.get("ruleId"):
            return True
    return False


def _waf_rule_group_matched_id(group):
    """Extract the matched rule ID from a ruleGroupList entry."""
    terminating = group.get("terminatingRule") or {}
    if terminating.get("ruleId"):
        return terminating.get("ruleId")
    for match in group.get("nonTerminatingMatchingRules", []) or []:
        if match.get("ruleId"):
            return match.get("ruleId")
    return None


def waf_rule_group_matches(event, rule_groups):
    """Check if any of the given WAF rule groups matched in the event."""
    rule_groups = _waf_normalize_groups(rule_groups)

    if _waf_matches_any_group(event.get("terminatingRuleId", ""), rule_groups):
        return True

    for matching_rule in event.get("nonTerminatingMatchingRules", []) or []:
        if _waf_matches_any_group(matching_rule.get("ruleId", ""), rule_groups):
            return True

    for group in event.get("ruleGroupList", []) or []:
        if not _waf_matches_any_group(group.get("ruleGroupId", ""), rule_groups):
            continue
        if _waf_rule_group_has_match(group):
            return True

    return False


def waf_get_matched_rule(event, rule_groups):
    """Extract the specific rule ID that matched within the given rule groups."""
    rule_groups = _waf_normalize_groups(rule_groups)

    for group in event.get("ruleGroupList", []) or []:
        if not _waf_matches_any_group(group.get("ruleGroupId", ""), rule_groups):
            continue
        matched = _waf_rule_group_matched_id(group)
        if matched:
            return matched
    return event.get("terminatingRuleId", "unknown")


def waf_alert_context(event, rule_groups):
    """Build standard alert context for WAF managed rule group detections."""
    if isinstance(rule_groups, str):
        rule_groups = [rule_groups]

    http_request = event.get("httpRequest", {})
    headers = http_request.get("headers", [])
    user_agent = next(
        (h.get("value") for h in headers if h.get("name", "").lower() == "user-agent"), None
    )

    context = {
        "rule_groups": rule_groups,
        "matched_rule": waf_get_matched_rule(event, rule_groups),
        "client_ip": http_request.get("clientIp"),
        "country": http_request.get("country"),
        "http_method": http_request.get("httpMethod"),
        "uri": http_request.get("uri"),
        "user_agent": user_agent,
        "action": event.get("action"),
        "source": event.get("httpSourceName"),
        "source_id": event.get("httpSourceId"),
        "terminating_rule_id": event.get("terminatingRuleId"),
        "terminating_rule_type": event.get("terminatingRuleType"),
    }

    terminating_matches = event.get("terminatingRuleMatchDetails", [])
    if terminating_matches:
        context["matched_data"] = [
            {
                "condition_type": m.get("conditionType"),
                "location": m.get("location"),
                "matched_strings": m.get("matchedData", []),
            }
            for m in terminating_matches
        ]

    return context


def waf_severity(event):
    """Dynamic severity based on WAF action."""
    action = event.get("action", "")
    if action == "ALLOW":
        return "CRITICAL"
    if action == "BLOCK":
        return "HIGH"
    if action == "COUNT":
        return "MEDIUM"
    return "DEFAULT"
