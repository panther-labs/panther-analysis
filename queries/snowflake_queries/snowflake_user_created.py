import re

_CREATE_USER_RE = re.compile(
    r"CREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?(\S+)", re.IGNORECASE
)


def rule(_):
    return True


def title(event):
    match = _CREATE_USER_RE.search(event.get("query_text", ""))
    username = match.group(1) if match else "<UNKNOWN_USER>"
    return (
        f"Snowflake user [{username}] created by "
        f"[{event.get('user_name', '<UNKNOWN_ADMIN>')}]"
    )
