import re

from panther_snowflake_helpers import query_history_alert_context

CREATE_USER_EXPR = re.compile(r"create user (\w+).*", flags=re.I)

CREATE_USER = ""


def rule(event):
    # pylint: disable=global-statement
    global CREATE_USER
    CREATE_USER = CREATE_USER_EXPR.match(event.get("QUERY_TEXT", ""))
    return all(
        (
            event.get("EXECUTION_STATUS") == "SUCCESS",
            event.get("QUERY_TYPE") == "CREATE_USER",
            CREATE_USER is not None,
        )
    )


def title(event):
    # pylint: disable=global-statement
    global CREATE_USER
    new_user = CREATE_USER.group(1)
    actor = event.get("user_name", "<UNKNOWN ACTOR>")
    source = event.get("p_source_label", "<UNKNOWN SOURCE>")
    return f"{source}: Snowflake user {new_user} created by {actor}"


def alert_context(event):
    return query_history_alert_context(event)
