def rule(event):
    actor_domain = event.deep_get("actor", "user", "email", default="@").split("@")[-1]

    if event.deep_get("event_type", "_tag", default="") == "shared_content_add_member":
        participants = event.get("participants", [{}])
        for participant in participants:
            email = participant.get("user", {}).get("email", "@")
            if email.split("@")[-1] != actor_domain:
                return True
    return False


def title(event):
    actor = event.deep_get("actor", "user", "email", default="<ACTOR_NOT_FOUND>")
    actor_domain = event.deep_get("actor", "user", "email", default="@").split("@")[-1]
    assets = [e.get("display_name", "") for e in event.get("assets", [{}])]
    participants = event.get("participants", [{}])
    external_participants = []
    for participant in participants:
        email = participant.get("user", {}).get("email", "")
        if email.split("@")[-1] != actor_domain:
            external_participants.append(email)
    return f"Dropbox: [{actor}] shared [{assets}] with external user [{external_participants}]."


def alert_context(event):
    actor_domain = event.deep_get("actor", "user", "email", default="@").split("@")[-1]
    external_participants = []
    participants = event.get("participants", [{}])
    for participant in participants:
        email = participant.get("user", {}).get("email", "")
        if email.split("@")[-1] != actor_domain:
            external_participants.append(email)
    return {"external_participants": external_participants}
