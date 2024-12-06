from panther_base_helpers import deep_get


def rule(event):
    return event.get("status") == "OPEN" and event.get("severity") != "INFORMATIONAL"


def title(event):
    return (
        f"[Wiz Alert]: "
        f"{event.deep_get('sourceRule', 'name', default='ALERT_DESCRIPTION_NOT_FOUND')}"
    )


def severity(event):
    return event.get("severity")


def dedup(event):
    # For lower-severity events, dedup based on specific source rule to reduce overall alert volume
    if event.get("severity") in ("INFO", "LOW"):
        dedup_str = str(event.deep_get("sourceRule", "id"))
        if dedup_str:
            return dedup_str
    # If the severity is higher, or for some reason we couldn't generate a dedup string based on
    #   the source rule, then use the alert severity + the resource ID itself.
    return event.deep_get(
        "entitySnapshot", "externalId", default="<RESOURCE_NOT_FOUND>"
    ) + event.get("severity", "<SEVERITY_NOT_FOUND>")


def description(event):
    return event.deep_get("sourceRule", "controlDescription", default="<DESCRIPTION_NOT_FOUND>")


def runbook(event):
    return event.deep_get(
        "sourceRule", "resolutionRecommendation", default="<RECOMMENDATION_NOT_FOUND>"
    )


def alert_context(event):
    security_subcategories = event.deep_get("sourceRule", "securitySubCategories", default=[{}])
    return {
        "id": event.get("id", "<ID_NOT_FOUND>"),
        "type": event.get("type", "<TYPE_NOT_FOUND>"),
        "entity_snapshot": event.get("entitySnapshot", {}),
        "mitre_attack_categories": [
            subcategory
            for subcategory in security_subcategories
            if deep_get(subcategory, "category", "framework", "name") == "MITRE ATT&CK Matrix"
        ],
    }
