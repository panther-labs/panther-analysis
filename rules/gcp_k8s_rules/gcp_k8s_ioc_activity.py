from gcp_base_helpers import gcp_alert_context


def rule(event):
    if event.deep_get("operation", "producer") == "k8s.io" and event.deep_get(
        "p_enrichment", "tor_exit_nodes"
    ):
        return True
    return False


def title(event):
    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="<ACTOR_NOT_FOUND>"
    )
    operation = event.deep_get("protoPayload", "methodName", default="<OPERATION_NOT_FOUND>")
    project_id = event.deep_get("resource", "labels", "project_id", default="<PROJECT_NOT_FOUND>")

    return f"[GCP]: [{actor}] performed [{operation}] on project [{project_id}]"


def alert_context(event):
    context = gcp_alert_context(event)
    context["tor_exit_nodes"] = event.deep_get("p_enrichment", "tor_exit_nodes")
    return context
