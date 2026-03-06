from panther_kubernetes_helpers import is_failed_request, is_system_principal, k8s_alert_context

# Admission controller webhook resource types
WEBHOOK_RESOURCES = {
    "mutatingwebhookconfigurations",
    "validatingwebhookconfigurations",
}


def rule(event):
    verb = event.udm("verb")
    resource = event.udm("resource")
    response_status = event.udm("responseStatus")

    # Only check webhook creation events
    if verb != "create":
        return False

    if resource not in WEBHOOK_RESOURCES:
        return False

    # Skip failed requests
    if is_failed_request(response_status):
        return False

    # Exclude noise from cluster maintenance
    username = event.udm("username")
    if is_system_principal(username):
        return False

    # Alert on any admission controller webhook creation
    return True


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    resource = event.udm("resource") or "webhook"
    name = event.udm("name") or "<UNKNOWN_NAME>"

    webhook_type = "Mutating" if "mutating" in resource.lower() else "Validating"

    return f"[{username}] created {webhook_type} admission controller webhook [{name}] "


def dedup(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    return f"k8s_admission_webhook_{username}"


def severity(event):
    """Increase severity for webhooks that intercept all resources."""
    webhooks = event.udm("webhooks") or []

    for webhook in webhooks:
        rules = webhook.get("rules", [])
        for rule_config in rules:
            resources = rule_config.get("resources", [])
            api_groups = rule_config.get("apiGroups", [])

            # Check for wildcard rules that intercept everything
            if "*" in resources or "*" in api_groups:
                return "HIGH"

    return "MEDIUM"


def alert_context(event):
    webhooks = event.udm("webhooks") or []

    # Extract webhook details
    webhook_details = []
    for webhook in webhooks:
        client_config = webhook.get("clientConfig", {})
        webhook_details.append(
            {
                "name": webhook.get("name"),
                "url": client_config.get("url"),
                "service": client_config.get("service"),
                "failure_policy": webhook.get("failurePolicy"),
                "rules": webhook.get("rules", []),
            }
        )

    return k8s_alert_context(
        event,
        extra_fields={
            "webhook_name": event.udm("name"),
            "webhook_type": event.udm("resource"),
            "webhooks": webhook_details,
        },
    )
