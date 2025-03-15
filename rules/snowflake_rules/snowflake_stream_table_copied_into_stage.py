import re

STAGE_EXPR = re.compile(r"COPY\s+INTO\s+(?:\$\$|')?@([\w\.]+)", flags=re.I)
PATH_EXPR = re.compile(r"COPY\s+INTO\s+(?:\$\$|')?@([\w\./]+)(?:\$\$|')?\s+FROM", flags=re.I)

STAGE = ""


def rule(event):
    # pylint: disable=global-statement
    global STAGE
    STAGE = STAGE_EXPR.match(event.get("QUERY_TEXT", ""))
    return all(
        (
            event.get("QUERY_TYPE") == "UNLOAD",
            STAGE is not None,
            event.get("EXECUTION_STATUS") == "SUCCESS",
        )
    )


def alert_context(event):
    # pylint: disable=global-statement
    global STAGE
    path = PATH_EXPR.match(event.get("QUERY_TEXT", ""))
    return {"actor": event.get("USER_NAME"), "path": path.group(1), "stage": STAGE.group(1).lower()}
