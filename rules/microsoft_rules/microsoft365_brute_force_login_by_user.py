def rule(event):
    return event.get("Operation", "") == "UserLoginFailed"


def title(event):
    return "Microsoft365 Brute Force Login Attempt " f"[{event.get('UserId')}]"
