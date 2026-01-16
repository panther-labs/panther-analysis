from panther_azureactivity_helpers import azure_activity_alert_context, azure_parse_json_string

POLICY_AUDIT_OPERATIONS = [
    "MICROSOFT.AUTHORIZATION/POLICIES/AUDIT/ACTION",
    "MICROSOFT.AUTHORIZATION/POLICIES/AUDITIFNOTEXISTS/ACTION",
]
POLICY_CATEGORY = "Policy"
WARNING_LEVEL = "Warning"


def rule(event):
    # Detects Azure Policy violations (audit failures) that indicate resources
    # are not compliant with assigned Azure Policies.
    return all(
        [
            event.get("operationName", "").upper() in POLICY_AUDIT_OPERATIONS,
            event.get("category", "") == POLICY_CATEGORY,
            event.get("level", "") == WARNING_LEVEL,
        ]
    )


def title(event):
    entity = event.deep_get("properties", "entity", default="<UNKNOWN_RESOURCE>")

    # Extract first policy name if available
    policies_json = event.deep_get("properties", "policies", default="[]")
    policies = azure_parse_json_string(policies_json)
    if policies and isinstance(policies, list) and len(policies) > 0:
        policy_name = policies[0].get("policyDefinitionDisplayName", "<UNKNOWN_POLICY>")
    else:
        policy_name = "<UNKNOWN_POLICY>"
    return f"Azure Policy Violation: [{policy_name}] on [{entity}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    # Add policy-specific context
    context["entity"] = event.deep_get("properties", "entity", default=None)
    context["message"] = event.deep_get("properties", "message", default=None)
    context["is_compliance_check"] = event.deep_get("properties", "isComplianceCheck", default=None)
    context["resource_location"] = event.deep_get("properties", "resourceLocation", default=None)
    return context
