def rule(event):
    cluster = event.get("cluster_name", "")
    user_domain = event.get("user", "@").split("@")[-1]
    return (
        event.get("event") == "user.login"
        and event.get("success") is True
        and event.get("method") == "saml"
        and not cluster.endswith(user_domain)
    )


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into "
        f"[{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] using SAML from a different domain"
    )
