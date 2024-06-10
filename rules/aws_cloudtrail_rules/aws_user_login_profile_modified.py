from panther_base_helpers import aws_rule_context


def rule(event):
    return (
        event.udm("event_source", default="") == "iam.amazonaws.com"
        and event.udm("event_name", default="") == "UpdateLoginProfile"
        and not event.udm("password_reset_required", default=False)
        and not event.udm("user_arn", default="").endswith(f"/{event.udm('user_name', default='')}")
    )


def title(event):
    return (
        f"User [{event.udm('user_arn').split('/')[-1]}] "
        f"changed the password for "
        f"[{event.udm('user_name')}]"
    )


def alert_context(event):
    return aws_rule_context(event)
