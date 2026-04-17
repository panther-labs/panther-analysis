def rule(event):
    return event.get("event") == "saml.created"


def title(event):
    return (
        f"A SAML connector was created or updated by User [{event.get('user', '<UNKNOWN_USER>')}] "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}]"
    )
