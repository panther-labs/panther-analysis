from panther_azureactivity_helpers import azure_activity_alert_context

ADVISOR_RECOMMENDATION_OPERATION = "MICROSOFT.ADVISOR/RECOMMENDATIONS/AVAILABLE/ACTION"
RECOMMENDATION_CATEGORY = "Recommendation"
SECURITY_CATEGORY = "Security"


def rule(event):
    return all(
        [
            event.get("operationName", "").upper() == ADVISOR_RECOMMENDATION_OPERATION,
            event.get("category", "") == RECOMMENDATION_CATEGORY,
            event.deep_get("properties", "recommendationCategory") == SECURITY_CATEGORY,
        ]
    )


def title(event):
    resource_id = event.get("resourceId", "<UNKNOWN_RESOURCE>")

    return f"Azure Advisor Security Recommendation Available for [{resource_id}]"


def alert_context(event):
    context = azure_activity_alert_context(event)
    context["recommendation_name"] = event.deep_get(
        "properties", "recommendationName", default=None
    )
    context["recommendation_impact"] = event.deep_get(
        "properties", "recommendationImpact", default=None
    )
    context["recommendation_category"] = event.deep_get(
        "properties", "recommendationCategory", default=None
    )
    context["recommendation_type"] = event.deep_get(
        "properties", "recommendationType", default=None
    )
    context["recommendation_link"] = event.deep_get(
        "properties", "recommendationResourceLink", default=None
    )
    context["result_description"] = event.get("resultDescription", None)

    return context
