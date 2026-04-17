from panther_azureactivity_helpers import (
    azure_activity_alert_context,
    azure_activity_success,
    extract_resource_name_from_id,
)

POLICY_OPERATIONS = [
    "MICROSOFT.AUTHORIZATION/POLICIES/DEPLOYIFNOTEXISTS/ACTION",
]


def rule(event):
    return event.get("operationName", "").upper() in POLICY_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    policy_name = extract_resource_name_from_id(
        resource_id, "policyDefinitions", default="<UNKNOWN_POLICY>"
    )

    return f"Azure Policy DeployIfNotExists Triggered: [{policy_name}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")

    policy_name = extract_resource_name_from_id(resource_id, "policyDefinitions", default="")
    if policy_name:
        context["policy_name"] = policy_name

    policy_assignment = extract_resource_name_from_id(resource_id, "policyAssignments", default="")
    if policy_assignment:
        context["policy_assignment"] = policy_assignment

    return context
