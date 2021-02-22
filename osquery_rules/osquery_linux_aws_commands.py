import shlex

from panther_base_helpers import deep_get

PLATFORM_IGNORE_LIST = {"darwin"}


def rule(event):
    # Filter out irrelevant logs & systems
    if (
        event.get("action") != "added"
        or "shell_history" not in event.get("name")
        or deep_get(event, "decorations", "platform") in PLATFORM_IGNORE_LIST
    ):
        return False

    command = deep_get(event, "columns", "command")
    if not command:
        return False
    try:
        command_args = shlex.split(command)
    except ValueError:
        # "No escaped character" or "No closing quotation", probably an invalid command
        return False

    if command_args[0] == "aws":
        return True

    return False


def title(event):
    return (
        f"User [{deep_get(event, 'columns', 'username', default='<UNKNOWN_USER>')}] issued an"
        f" aws-cli command on [{event.get('hostIdentifier', '<UNKNOWN_HOST>')}]"
    )
