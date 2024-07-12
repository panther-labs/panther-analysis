import urllib.parse
from panther_base_helpers import deep_get

# update to username value for mapping in aws-auth configmap or eks access entries api
# docs: https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html#creating-access-entries
CLUSTER_ADMIN_USERNAMES = []

# update to production environment source labels
PROD_SOURCE_LABELS = []

def get_exec_command(request_uri: str) -> str:
    """Takes the requesturi from an Kubernetes Audit Log event for
    an exec call and url decodes it, then returns it as a string

    example input:

    "/api/v1/namespaces/n/pods/pod/exec?command=sh&command=-c
    &command=command+-v+bash+%3E%2Fdev%2Fnull+%26%26+exec+bash+%7C%7C+exec+sh&container=pod
    &stdin=true&stdout=true&tty=true"

    example output:

    "sh -c command -v bash >/dev/null && exec bash || exec sh"

    Args:
        request_uri (str): The request

    Returns:
        str: _description_
    """

    decoded_uri = urllib.parse.unquote(request_uri)
    parsed_uri = urllib.parse.urlparse(decoded_uri)

    if not parsed_uri.path.startswith("/api/v1/namespaces"):
        return ""

    if not parsed_uri.path.endswith("/exec"):
        return ""

    query_params = urllib.parse.parse_qs(parsed_uri.query)
    exec_command = ""

    if "command" in query_params:
        exec_command = " ".join(query_params["command"])

    return exec_command


def rule(event):
    k8s_username = deep_get(event, "user", "username")
    verb = event.get("verb")
    source_label = event.get("p_source_label")
    subresource = deep_get(event, "objectref", "subresource")

    return (
        subresource == "exec"
        and k8s_username in CLUSTER_ADMIN_USERNAMES
        and source_label in PROD_SOURCE_LABELS
        and verb == "create"
    )

def title(event):
    user = deep_get(event, "user", "extra", "sessionName", default=["NOT FOUND"])[0]
    k8s_username = deep_get(event, "user", "username")

    return f"Exec into production EKS pod detected user: {user} as {k8s_username}"


def alert_context(event):
    request_uri = event.get("requesturi")

    namespace = deep_get(event, "objectref", "namespace")
    resource_name = deep_get(event, "objectref", "name")
    command = get_exec_command(request_uri)
    audit_log_timestamp = event.get("requestreceivedtimestamp")
    useragent = event.get("useragent")

    return {
        "namespace": namespace,
        "resource_name": resource_name,
        "command": command,
        "audit_log_timestamp": audit_log_timestamp,
        "useragent": useragent,
    }


def dedup(event):
    namespace = deep_get(event, "objectref", "namespace")
    resource_name = deep_get(event, "objectref", "name")
    useragent = event.get("useragent")
    user = deep_get(event, "user", "extra", "sessionName", default="NOT FOUND")

    return f"{namespace}-{resource_name}-{user[0]}-{useragent}"
