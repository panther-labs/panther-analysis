def rule(event):
    if event.deep_get("action", default="") in [
        "ssh_certificate_authority.create",
        "ssh_certificate_requirement.disable",
    ]:
        return True
    return False
