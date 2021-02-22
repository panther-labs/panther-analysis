def rule(event):
    if "osx-attacks" not in event.get("name", ""):
        return False

    # There is another rule specifically for this query
    if "Keyboard_Event_Taps" in event.get("name", ""):
        return False

    if event.get("action") != "added":
        return False

    return True


def title(event):
    return "MacOS malware detected on [{}]".format(event.get("hostIdentifier"))
