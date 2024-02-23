from panther_base_helpers import deep_get


def rule(event):
    if deep_get(event, "operation", "producer") == "k8s.io" and deep_get(
        event, "p_enrichment", "tor_exit_nodes"
    ):
        return True
    return False
