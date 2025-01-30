def rule(event):
    if event.get("DELETED_ON"):
        return False
    return "admin" in event.get("GRANTEE_NAME", "").lower()


def title(event):
    source_name = event.get("p_source_label", "<UNKNOWN SNOWFLAKE SOURCE>")
    target = event.get("GRANTED_TO", "<UNKNOWN TARGET>")
    actor = event.get("GRANTED_BY", "<UNKNOWN ACTOR>")
    role = event.get("GRANTEE_NAME", "<UNKNOWN ROLE>")
    return f"{source_name}: {actor} granted role {role} to {target}"
