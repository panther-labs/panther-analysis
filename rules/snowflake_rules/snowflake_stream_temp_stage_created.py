import re

from panther_snowflake_helpers import query_history_alert_context

STAGE_EXPR = re.compile(
    (
        r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+|TEMP\s+)STAGE\s+"
        r"(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_\\.]+)"
    ),
    flags=re.I,
)

STAGE = ""


def rule(event):
    # pylint: disable=global-statement
    global STAGE
    STAGE = STAGE_EXPR.match(event.get("QUERY_TEXT", ""))

    return all(
        (
            event.get("QUERY_TYPE") == "CREATE",
            event.get("EXECUTION_STATUS") == "SUCCESS",
            STAGE is not None,
        )
    )


def alert_context(event):
    # pylint: disable=global-statement
    global STAGE
    return query_history_alert_context(event) | {"stage": STAGE.group(1).lower()}
