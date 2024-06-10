def rule(event):
    return (
        event.udm("event_name") == "ModifyDBInstance"
        and event.udm("event_source") == "rds.amazonaws.com"
        and bool(event.udm("master_user_password"))
    )


def title(event):
    return f"RDS Master Password Updated on [{event.udm('db_instance_arn')}]"
