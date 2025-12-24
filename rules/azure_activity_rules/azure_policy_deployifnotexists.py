from panther_azureactivity_helpers import azure_activity_alert_context, azure_activity_success

POLICY_OPERATIONS = [
    "MICROSOFT.AUTHORIZATION/POLICIES/DEPLOYIFNOTEXISTS/ACTION",
]


def rule(event):
    return event.get("operationName", "").upper() in POLICY_OPERATIONS and azure_activity_success(
        event
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")
    caller = event.get("callerIpAddress", "<UNKNOWN_CALLER>")

    # Extract policy name from resource ID
    policy_name = "<UNKNOWN_POLICY>"
    if resource_id:
        parts = resource_id.split("/")
        # Policy definitions typically appear after 'policyDefinitions' in the path
        if "policyDefinitions" in parts:
            try:
                policy_name = parts[parts.index("policyDefinitions") + 1]
            except (IndexError, ValueError):
                pass

    return f"Azure Policy DeployIfNotExists Triggered: [{policy_name}] by [{caller}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    resource_id = event.get("resourceId", "")
    if resource_id:
        parts = resource_id.split("/")

        # Extract policy-related information
        if "policyDefinitions" in parts:
            try:
                context["policy_name"] = parts[parts.index("policyDefinitions") + 1]
            except (IndexError, ValueError):
                pass

        if "policyAssignments" in parts:
            try:
                context["policy_assignment"] = parts[parts.index("policyAssignments") + 1]
            except (IndexError, ValueError):
                pass

    return context
