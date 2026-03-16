def rule(event):
    return event.get("GRANTEE_NAME").lower() == "public"


def title(event):
    return (
        f"{event.get('p_source_label', '<UNKNOWN LOG SOURCE>')}: "
        f"{event.get('GRANTED_BY', '<UNKNOWN ACTOR>')} made changes to the PUBLIC role"
    )
