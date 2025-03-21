from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    return event.get("name") == "download"


def title(event: PantherEvent) -> str:
    actor = event.deep_get("actor", "email", default="<UNKNWON ACTOR>")
    return f"{actor} downloaded an escessive number of documents."


def alert_context(event: PantherEvent) -> dict:
    return {
        "actor": event.deep_get("actor", "email", default="<UNKNOWN ACTOR>"),
        "document_name": event.deep_get("parameters", "doc_title", default="<UNKNOWN DOCUMENT>")
    }
