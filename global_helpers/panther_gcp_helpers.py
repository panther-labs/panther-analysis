def get_info(event):
    fields = {
        "principal": "protoPayload.authenticationInfo.principalEmail",
        "project_id": "protoPayload.resource.labels.project_id",
        "caller_ip": "protoPayload.requestMetadata.callerIP",
        "user_agent": "protoPayload.requestMetadata.callerSuppliedUserAgent",
        "method_name": "protoPayload.methodName",
    }
    return {name: event.deep_get(*(path.split("."))) for name, path in fields.items()}


def get_k8s_info(event):
    """
    Get GCP K8s info such as pod, authorized user etc.
    return a tuple of strings
    """
    pod_slug = event.deep_get("protoPayload", "resourceName")
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
    return {name: event.deep_get(*(path.split("."))) for name, path in fields.items()}


def gcp_alert_context(event):
    return {
        "project": event.deep_get("resource", "labels", "project_id", default=""),
        "principal": event.deep_get(
            "protoPayload", "authenticationInfo", "principalEmail", default=""
        ),
        "caller_ip": event.deep_get("protoPayload", "requestMetadata", "callerIP", default=""),
        "methodName": event.deep_get("protoPayload", "methodName", default=""),
        "resourceName": event.deep_get("protoPayload", "resourceName", default=""),
        "serviceName": event.deep_get("protoPayload", "serviceName", default=""),
    }


def get_binding_deltas(event):
    """A GCP helper function to return the binding deltas from audit events

    Binding deltas provide context on a permission change, including the
    action, role, and member associated with the request.
    """
    if event.get("protoPayload", {}).get("methodName") != "SetIamPolicy":
        return []

    service_data = event.get("protoPayload", {}).get("serviceData")
    if not service_data:
        return []

    binding_deltas = service_data.get("policyDelta", {}).get("bindingDeltas")
    if not binding_deltas:
        return []
    return binding_deltas
