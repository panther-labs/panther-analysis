def rule(event):
    if event.deep_get("eventTypeName", default="") != "INVITED_TO_ORG":
        return False

    user_who_sent_an_invitation = event.deep_get("username", default="")
    user_who_was_invited = event.deep_get("targetUsername", default="")
    domain = user_who_sent_an_invitation.split("@")[-1]

    email_domains_are_different = not user_who_was_invited.endswith(domain)
    return email_domains_are_different


def title(event):
    actor = event.get("username", "<USER_NOT_FOUND>")
    target = event.get("targetUsername", "<USER_NOT_FOUND>")
    org_id = event.get("orgId", "<ORG_NOT_FOUND>")
    return f"MongoDB Atlas: [{actor}] invited external user [{target}] to the org [{org_id}]"


def alert_context(event):
    return {
        "username": event.get("username", "<USER_NOT_FOUND>"),
        "target_username": event.get("targetUsername", "<USER_NOT_FOUND>"),
        "org_id": event.get("orgId", "<ORG_NOT_FOUND>"),
    }
