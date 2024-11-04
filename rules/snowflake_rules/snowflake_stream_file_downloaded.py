import re

from panther_snowflake_helpers import query_history_alert_context

PATH_EXPR = re.compile(r"'file:\/\/([\/\w\.]+)'", flags=re.I)
STAGE_EXPR = re.compile(r"GET\s+'(@[\w\.\/\@\%]+)'", flags=re.I)

PATH = ""
STAGE = ""


def rule(event):
    # pylint: disable=global-statement
    # Check these conditions first to avoid running an expensive regex on every log
    if not all(
        (
            event.get("QUERY_TYPE") == "GET_FILES",
            event.get("EXECUTION_STATUS") == "SUCCESS",
            # Avoid alerting for fetching worksheets:
            event.get("QUERY_TEXT") != "GET '@~/worksheet_data/metadata' 'file:///'",
        )
    ):
        return False

    global PATH
    PATH = PATH_EXPR.search(event.get("QUERY_TEXT", ""))

    return PATH is not None


def alert_context(event):
    # pylint: disable=global-statement
    global PATH
    global STAGE
    STAGE = STAGE_EXPR.match(event.get("QUERY_TEXT", ""))
    return query_history_alert_context(event) | {
        "path": PATH.group(1),
        "stage": None if not STAGE else STAGE.group(1),
    }
