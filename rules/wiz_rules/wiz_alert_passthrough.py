def rule(event):
    return event.get("status") == "OPEN"


def title(event):
    return (
        f"[Wiz Alert]: "
        f"{event.deep_get('sourceRule', 'name', default='ALERT_DESCRIPTION_NOT_FOUND')}"
    )


def severity(event):
    return event.get("severity")


def dedup(event):
    return event.get("id")


def alert_context(event):
    return {
        "id": event.get("id", "<ID_NOT_FOUND>"),
        "type": event.get("type", "<TYPE_NOT_FOUND>"),
        "description": event.deep_get(
            "sourceRule", "controlDescription", default="<DESCRIPTION_NOT_FOUND>"
        ),
        "resolution_recommendation": event.deep_get(
            "sourceRule", "resolutionRecommendation", default="<RECOMMENDATION_NOT_FOUND>"
        ),
        "severity": event.get("severity", "<SEVERITY_NOT_FOUND>"),
        "entity_snapshot": event.get("entitySnapshot", {}),
    }
