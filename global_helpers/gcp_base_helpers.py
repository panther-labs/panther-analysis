from panther_base_helpers import deep_get


def get_info(event):
    fields = {
        "principal": "protoPayload.authenticationInfo.principalEmail",
        "project_id": "protoPayload.resource.labels.project_id",
        "caller_ip": "protoPayload.requestMetadata.callerIP",
        "user_agent": "protoPayload.requestMetadata.callerSuppliedUserAgent",
        "method_name": "protoPayload.methodName",
    }
    return {name: deep_get(event, *(path.split("."))) for name, path in fields.items()}


def get_k8s_info(event):
    """
    Get GCP K8s info such as pod, authorized user etc.
    return a tuple of strings
    """
    pod_slug = deep_get(event, "protoPayload", "resourceName")
    # core/v1/namespaces/<namespace>/pods/<pod-id>/<action>
    _, _, _, namespace, _, pod, _ = pod_slug.split("/")
    return get_info(event) | {"namespace": namespace, "pod": pod}


def get_flow_log_info(event):
    fields = {
        "src_ip": "jsonPayload.connection.src_ip",
        "dest_ip": "jsonPayload.connection.dest_ip",
        "src_port": "jsonPayload.connection.src_port",
        "dest_port": "jsonPayload.connection.dest_port",
        "protocol": "jsonPayload.connection.protocol",
        "bytes_sent": "jsonPayload.bytes_sent",
        "reporter": "jsonPayload.reporter",
    }
    return {name: deep_get(event, *(path.split("."))) for name, path in fields.items()}


def gcp_alert_context(event):
    return {
        "project": deep_get(event, "protoPayload", "resource", "labels", "project_id", default=""),
        "principal": deep_get(
            event, "protoPayload", "authenticationInfo", "principalEmail", default=""
        ),
        "caller_ip": deep_get(event, "protoPayload", "requestMetadata", "callerIP", default=""),
        "methodName": deep_get(event, "protoPayload", "methodName", default=""),
        "resourceName": deep_get(event, "protoPayload", "resourceName", default=""),
        "serviceName": deep_get(event, "protoPayload", "serviceName", default=""),
    }
