from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    if event.deep_get("id", "applicationName") != "drive":
        return False
    return event.get("name") == "download"


def alert_context(event: PantherEvent) -> dict:
    return {
        "actor": event.deep_get("actor", "email", default="<UNKNOWN ACTOR>"),
        "document_name": event.deep_get("parameters", "doc_title", default="<UNKNOWN DOCUMENT>"),
    }
