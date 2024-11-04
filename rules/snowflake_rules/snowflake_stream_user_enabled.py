import re

from panther_snowflake_helpers import query_history_alert_context

USER_ENABLED_EXPR = re.compile(r"alter\s+user\s+(.+?)\s+.*?set\s+disabled\s*=\s*false", flags=re.I)

USER_ENABLED = ""


def rule(event):
    # pylint: disable=global-statement
    global USER_ENABLED
    USER_ENABLED = USER_ENABLED_EXPR.match(event.get("QUERY_TEXT", ""))

    # Exit out early to avoid needless regex
    return all(
        (
            event.get("QUERY_TYPE") == "ALTER_USER",
            event.get("EXECUTION_STATUS") == "SUCCESS",
            USER_ENABLED is not None,
        )
    )


def title(event):
    # pylint: disable=global-statement
    global USER_ENABLED
    enabled_user = USER_ENABLED.group(1)
    actor = event.get("USER_NAME", "<UNKNOWN ACTOR>")
    source = event.get("p_source_label", "<UNKNOWN SOURCE>")
    return f"{source}: Snowflake user {enabled_user} enabled by {actor}"


def alert_context(event):
    return query_history_alert_context(event)
