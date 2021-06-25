def rule(event):
    return (
        event.get("source_type") == "account_setting"
        and event.get("action", "")
        in {
            "create",
            "update",
        }
        and event.get("source_label", "").lower() in {"account assumption", "assumption duration"}
    )


def title(event):
    return (
        f"A user [{event.udm('actor_user')}] updated zendesk support user assumption settings"
    )
