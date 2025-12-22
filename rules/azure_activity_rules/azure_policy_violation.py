import json

from panther_azureactivity_helpers import azure_activity_alert_context

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
    policy_name = "<UNKNOWN_POLICY>"
    try:
        policies_json = event.deep_get("properties", "policies", default="[]")
        if isinstance(policies_json, str):
            policies = json.loads(policies_json)
            if policies and isinstance(policies, list) and len(policies) > 0:
                policy_name = policies[0].get("policyDefinitionDisplayName", policy_name)
    except (json.JSONDecodeError, AttributeError, KeyError, IndexError):
        pass

    return f"Azure Policy Violation: [{policy_name}] on [{entity}]"


def alert_context(event):
    context = azure_activity_alert_context(event)

    # Add policy-specific context
    context["entity"] = event.deep_get("properties", "entity", default=None)
    context["message"] = event.deep_get("properties", "message", default=None)
    context["is_compliance_check"] = event.deep_get("properties", "isComplianceCheck", default=None)
    context["resource_location"] = event.deep_get("properties", "resourceLocation", default=None)

    # Parse and extract first policy details
    try:
        policies_json = event.deep_get("properties", "policies", default="[]")
        if isinstance(policies_json, str):
            policies = json.loads(policies_json)
            if policies and isinstance(policies, list) and len(policies) > 0:
                first_policy = policies[0]
                context["policy_definition_name"] = first_policy.get("policyDefinitionDisplayName")
                context["policy_set_definition_name"] = first_policy.get(
                    "policySetDefinitionDisplayName"
                )
                context["policy_effect"] = first_policy.get("policyDefinitionEffect")
                context["policy_assignment_name"] = first_policy.get("policyAssignmentDisplayName")
                context["total_policies_violated"] = len(policies)
    except (json.JSONDecodeError, AttributeError, KeyError):
        pass

    return context
