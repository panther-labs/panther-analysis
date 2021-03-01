def rule(event):
    return "ossec-rootkit" in event.get("name", "") and event.get("action") == "added"


def title(event):
    return f"OSSEC rootkit found on [{event.get('hostIdentifier')}]"
