import json
import re

# panther_base_helpers_old.GSUITE_PARAMETER_VALUES is DEPRECATED!!!
# Instead use panther_gsuite_helpers.GSUITE_PARAMETER_VALUES
GSUITE_PARAMETER_VALUES = [
    "value",
    "intValue",
    "boolValue",
    "multiValue",
    "multiIntValue",
    "messageValue",
    "multiMessageValue",
]


def gsuite_parameter_lookup(parameters, key):
    """Global `gsuite_parameter_lookup` is DEPRECATED.
    Instead, use `from panther_gsuite_helpers import gsuite_parameter_lookup`."""
    for param in parameters:
        if param["name"] != key:
            continue
        for value in GSUITE_PARAMETER_VALUES:
            if value in param:
                return param[value]
        return None
    return None


def gsuite_details_lookup(detail_type, detail_names, event):
    """Global `gsuite_details_lookup` is DEPRECATED.
    Instead, use `from panther_gsuite_helpers import gsuite_details_lookup`."""
    for details in event.get("events", {}):
        if details.get("type") == detail_type and details.get("name") in detail_names:
            return details
    # not found, return empty dict
    return {}


# panther_base_helpers_old.ZENDESK_CHANGE_DESCRIPTION is DEPRECATED!!!
# Instead use panther_zendesk_helpers.ZENDESK_CHANGE_DESCRIPTION
ZENDESK_CHANGE_DESCRIPTION = "change_description"
# panther_base_helpers_old.ZENDESK_APP_ROLE_ASSIGNED is DEPRECATED!!!
# Instead use panther_zendesk_helpers.ZENDESK_APP_ROLE_ASSIGNED
ZENDESK_APP_ROLE_ASSIGNED = re.compile(
    r"(?P<app>.*) role changed from (?P<old_role>.+) to (?P<new_role>.*)", re.IGNORECASE
)
# panther_base_helpers_old.ZENDESK_ROLE_ASSIGNED is DEPRECATED!!!
# Instead use panther_zendesk_helpers.ZENDESK_ROLE_ASSIGNED
ZENDESK_ROLE_ASSIGNED = re.compile(
    r"Role changed from (?P<old_role>.+) to (?P<new_role>[^$]+)", re.IGNORECASE
)


def zendesk_get_roles(event):
    """Global `zendesk_get_roles` is DEPRECATED.
    Instead, use `from panther_zendesk_helpers import zendesk_get_roles`."""
    old_role = ""
    new_role = ""
    role_change = event.get(ZENDESK_CHANGE_DESCRIPTION, "")
    if "\n" in role_change:
        for app_change in role_change.split("\n"):
            matches = ZENDESK_APP_ROLE_ASSIGNED.match(app_change)
            if matches:
                if old_role:
                    old_role += " ; "
                old_role += matches.group("app") + ":" + matches.group("old_role")
                if new_role:
                    new_role += " ; "
                new_role += matches.group("app") + ":" + matches.group("new_role")
    else:
        matches = ZENDESK_ROLE_ASSIGNED.match(role_change)
        if matches:
            old_role = matches.group("old_role")
            new_role = matches.group("new_role")
    if not old_role:
        old_role = "<UNKNOWN_APP>:<UNKNOWN_ROLE>"
    if not new_role:
        new_role = "<UNKNOWN_APP>:<UNKNOWN_ROLE>"
    return old_role, new_role


def box_parse_additional_details(event: dict):
    """Global `box_parse_additional_details` is DEPRECATED.
    Instead, use `from panther_box_helpers import box_parse_additional_details`."""
    additional_details = event.get("additional_details", {})
    if isinstance(additional_details, (str, bytes)):
        try:
            return json.loads(additional_details)
        except ValueError:
            return {}
    return additional_details


def okta_alert_context(event: dict):
    """Global `okta_alert_context` is DEPRECATED.
    Instead, use `from panther_okta_helpers import okta_alert_context`."""
    return {
        "event_type": event.get("eventtype", ""),
        "severity": event.get("severity", ""),
        "actor": event.get("actor", {}),
        "client": event.get("client", {}),
        "request": event.get("request", {}),
        "outcome": event.get("outcome", {}),
        "target": event.get("target", []),
        "debug_context": event.get("debugcontext", {}),
        "authentication_context": event.get("authenticationcontext", {}),
        "security_context": event.get("securitycontext", {}),
        "ips": event.get("p_any_ip_addresses", []),
    }


def crowdstrike_detection_alert_context(event: dict):
    """Global `crowdstrike_detection_alert_context` is DEPRECATED.
    Instead, use `from panther_crowdstrike_fdr_helpers import crowdstrike_detection_alert_context`.
    """
    return {
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "user": get_crowdstrike_field(event, "UserName", default=""),
        "console-link": get_crowdstrike_field(event, "FalconHostLink", default=""),
        "commandline": get_crowdstrike_field(event, "CommandLine", default=""),
        "parentcommandline": get_crowdstrike_field(event, "ParentCommandLine", default=""),
        "filename": get_crowdstrike_field(event, "FileName", default=""),
        "filepath": get_crowdstrike_field(event, "FilePath", default=""),
        "description": get_crowdstrike_field(event, "DetectDescription", default=""),
        "action": get_crowdstrike_field(event, "PatternDispositionDescription", default=""),
    }


def crowdstrike_process_alert_context(event: dict):
    """Global `crowdstrike_process_alert_context` is DEPRECATED.
    Instead, use `from panther_crowdstrike_fdr_helpers import crowdstrike_process_alert_context`.
    """
    return {
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "CommandLine": get_crowdstrike_field(event, "CommandLine", default=""),
        "TargetProcessId": get_crowdstrike_field(event, "TargetProcessId", default=""),
        "RawProcessId": get_crowdstrike_field(event, "RawProcessId", default=""),
        "ParentBaseFileName": get_crowdstrike_field(event, "ParentBaseFileName", default=""),
        "ParentProcessId": get_crowdstrike_field(event, "ParentProcessId", default=""),
        "ImageFileName": get_crowdstrike_field(event, "ImageFileName", default=""),
        "SHA256Hash": get_crowdstrike_field(event, "SHA256HashData", default=""),
        "platform": get_crowdstrike_field(event, "event_platform", default=""),
    }


def crowdstrike_network_detection_alert_context(event: dict):
    """Global `crowdstrike_network_detection_alert_context` is DEPRECATED.
    Instead, use `from panther_crowdstrike_fdr_helpers
    import crowdstrike_network_detection_alert_context`.
    """
    return {
        "LocalAddressIP4": get_crowdstrike_field(event, "LocalAddressIP4", default=""),
        "LocalPort": get_crowdstrike_field(event, "LocalPort", default=""),
        "RemoteAddressIP4": get_crowdstrike_field(event, "RemoteAddressIP4", default=""),
        "RemotePort": get_crowdstrike_field(event, "RemotePort", default=""),
        "Protocol": get_crowdstrike_field(event, "Protocol", default=""),
        "event_simpleName": get_crowdstrike_field(event, "event_simpleName", default=""),
        "aid": get_crowdstrike_field(event, "aid", default=""),
        "ContextProcessId": get_crowdstrike_field(event, "ContextProcessId", default=""),
    }


def filter_crowdstrike_fdr_event_type(event, name: str) -> bool:
    """Global `filter_crowdstrike_fdr_event_type` is DEPRECATED.
    Instead, use `from panther_crowdstrike_fdr_helpers import filter_crowdstrike_fdr_event_type`.
    """
    if event.get("p_log_type") != "Crowdstrike.FDREvent":
        return False
    return event.get("fdr_event_type", "") != name


def get_crowdstrike_field(event, field_name, default=None):
    """Global `get_crowdstrike_field` is DEPRECATED.
    Instead, use `from panther_crowdstrike_fdr_helpers import get_crowdstrike_field`.
    """
    return (
        event.deep_get(field_name)
        or event.deep_get("event", field_name)
        or event.deep_get("unknown_payload", field_name)
        or default
    )


def slack_alert_context(event):
    """Global `slack_alert_context` is DEPRECATED.
    Instead, use `from panther_slack_helpers import slack_alert_context`."""
    return {
        "actor-name": event.deep_get("actor", "user", "name", default="<MISSING_NAME>"),
        "actor-email": event.deep_get("actor", "user", "email", default="<MISSING_EMAIL>"),
        "actor-ip": event.deep_get("context", "ip_address", default="<MISSING_IP>"),
        "user-agent": event.deep_get("context", "ua", default="<MISSING_UA>"),
    }


def github_alert_context(event):
    """Global `github_alert_context` is DEPRECATED.
    Instead, use `from panther_github_helpers import github_alert_context`."""
    return {
        "action": event.get("action", ""),
        "actor": event.get("actor", ""),
        "actor_location": event.deep_get("actor_location", "country_code"),
        "org": event.get("org", ""),
        "repo": event.get("repo", ""),
        "user": event.get("user", ""),
    }


def aws_strip_role_session_id(user_identity_arn):
    """Global `aws_strip_role_session_id` is DEPRECATED.
    Instead, use `from panther_aws_helpers import aws_strip_role_session_id`."""
    # The ARN structure is arn:aws:sts::123456789012:assumed-role/RoleName/<sessionId>
    arn_parts = user_identity_arn.split("/")
    if arn_parts:
        return "/".join(arn_parts[:2])
    return user_identity_arn


def aws_rule_context(event: dict):
    """Global `aws_rule_context` is DEPRECATED.
    Instead, use `from panther_aws_helpers import aws_rule_context`."""
    return {
        "eventName": event.get("eventName", "<MISSING_EVENT_NAME>"),
        "eventSource": event.get("eventSource", "<MISSING_ACCOUNT_ID>"),
        "awsRegion": event.get("awsRegion", "<MISSING_AWS_REGION>"),
        "recipientAccountId": event.get("recipientAccountId", "<MISSING_ACCOUNT_ID>"),
        "sourceIPAddress": event.get("sourceIPAddress", "<MISSING_SOURCE_IP>"),
        "userAgent": event.get("userAgent", "<MISSING_USER_AGENT>"),
        "userIdentity": event.get("userIdentity", "<MISSING_USER_IDENTITY>"),
    }


def aws_guardduty_context(event: dict):
    """Global `aws_guardduty_context` is DEPRECATED.
    Instead, use `from panther_aws_helpers import aws_guardduty_context`."""
    return {
        "description": event.get("description", "<MISSING DESCRIPTION>"),
        "severity": event.get("severity", "<MISSING SEVERITY>"),
        "id": event.get("id", "<MISSING ID>"),
        "type": event.get("type", "<MISSING TYPE>"),
        "resource": event.get("resource", {}),
        "service": event.get("service", {}),
    }


def eks_panther_obj_ref(event):
    """Global `eks_panther_obj_ref` is DEPRECATED.
    Instead, use `from panther_aws_helpers import eks_panther_obj_ref`."""
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


def get_binding_deltas(event):
    """Global `get_binding_deltas` is DEPRECATED.
    Instead, use `from panther_gcp_helpers import get_binding_deltas`."""
    if event.get("protoPayload", {}).get("methodName") != "SetIamPolicy":
        return []

    service_data = event.get("protoPayload", {}).get("serviceData")
    if not service_data:
        return []

    # Reference: bit.ly/2WsJdZS
    binding_deltas = service_data.get("policyDelta", {}).get("bindingDeltas")
    if not binding_deltas:
        return []
    return binding_deltas


def msft_graph_alert_context(event):
    """Global `msft_graph_alert_context` is DEPRECATED.
    Instead, use `from panther_msft_helpers import msft_graph_alert_context`."""
    return {
        "category": event.get("category", ""),
        "description": event.get("description", ""),
        "userStates": event.get("userStates", []),
        "fileStates": event.get("fileStates", []),
        "hostStates": event.get("hostStates", []),
    }


def m365_alert_context(event):
    """Global `m365_alert_context` is DEPRECATED.
    Instead, use `from panther_msft_helpers import m365_alert_context`."""
    return {
        "operation": event.get("Operation", ""),
        "organization_id": event.get("OrganizationId", ""),
        "client_ip": event.get("ClientIp", ""),
        "extended_properties": event.get("ExtendedProperties", []),
        "modified_properties": event.get("ModifiedProperties", []),
        "application": event.get("Application", ""),
        "actor": event.get("Actor", []),
    }
