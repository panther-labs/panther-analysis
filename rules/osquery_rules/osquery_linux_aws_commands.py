import shlex

PLATFORM_IGNORE_LIST = {"darwin"}


def rule(event):
    # Filter out irrelevant logs & systems
    if (
        event.get("action") != "added"
        or "shell_history" not in event.get("name")
        or event.deep_get("decorations", "platform") in PLATFORM_IGNORE_LIST
    ):
        return False

    command = event.deep_get("columns", "command")
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
        f"User [{event.deep_get('columns', 'username', default='<UNKNOWN_USER>')}] issued an"
        f" aws-cli command on [{event.get('hostIdentifier', '<UNKNOWN_HOST>')}]"
    )
