from panther_kubernetes_helpers import is_k8s_log, k8s_alert_context


def rule(event):
    # Check if this is a Kubernetes audit log with Tor exit node enrichment
    if is_k8s_log(event) and event.deep_get("p_enrichment", "tor_exit_nodes"):
        return True

    return False


def title(event):
    username = event.udm("username") or "<UNKNOWN_USER>"
    tor_nodes = event.deep_get("p_enrichment", "tor_exit_nodes", default=[])
    tor_ip = tor_nodes[0] if tor_nodes else "<UNKNOWN_IP>"

    return f"Kubernetes API activity from Tor exit node [{tor_ip}] by user [{username}]"


def dedup(event):
    tor_nodes = event.deep_get("p_enrichment", "tor_exit_nodes", default=[])
    tor_ip = tor_nodes[0] if tor_nodes else "<UNKNOWN_IP>"
    return f"k8s_tor_{tor_ip}"


def alert_context(event):
    return k8s_alert_context(
        event,
        extra_fields={"tor_exit_nodes": event.deep_get("p_enrichment", "tor_exit_nodes")},
    )
