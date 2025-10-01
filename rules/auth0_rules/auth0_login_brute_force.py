from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:  # noqa: ARG001
    return True


def title(event: PantherEvent) -> str:
    total_incidents = event.get("total_incidents", 5)
    return f"Auth0 Brute Force detected: {total_incidents} attempts in the past hour"
