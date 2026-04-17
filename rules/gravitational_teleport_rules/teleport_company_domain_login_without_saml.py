def rule(event):
    user_domain = event.get("user", "@").split("@")[-1]
    cluster = event.get("cluster_name", "")
    return bool(
        event.get("event") == "user.login"
        and event.get("success") is True
        and cluster.endswith(user_domain)
        and event.get("method") != "saml"
    )


def title(event):
    return (
        f"User [{event.get('user', '<UNKNOWN_USER>')}] logged into "
        f"[{event.get('cluster_name', '<UNNAMED_CLUSTER>')}] without using SAML"
    )
