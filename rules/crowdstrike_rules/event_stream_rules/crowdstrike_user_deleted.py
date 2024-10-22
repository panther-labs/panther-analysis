from panther_crowdstrike_event_streams_helpers import cs_alert_context


def rule(event):
    return all(
        [
            event.deep_get("event", "OperationName") == "deleteUser",
            event.deep_get("event", "Success"),
        ]
    )


def title(event):
    actor = event.deep_get("event", "UserId", default="UNKNOWN USER")
    return f"[{actor}] has deleted multiple Crowdstrike users within the past hour."


def alert_context(event):
    return cs_alert_context(event)
