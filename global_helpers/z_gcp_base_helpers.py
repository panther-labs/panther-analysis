import panther_base_helpers

def get_info(event):
    principal = panther_base_helpers.deep_get(event, 'protoPayload', 'authenticationInfo', 'principalEmail')
    project_id = panther_base_helpers.deep_get(event, 'protoPayload', 'resource', 'labels', 'project_id')
    caller_ip = panther_base_helpers.deep_get(event, 'protoPayload', 'requestMetadata', 'callerIP')
    user_agent = panther_base_helpers.deep_get(event, 'protoPayload', 'requestMetadata', 'callerSuppliedUserAgent')
    method_name = panther_base_helpers.deep_get(event, 'protoPayload', 'methodName')
    return principal, project_id, caller_ip, user_agent, method_name


def get_k8s_info(event):
    '''
    Get GCP K8s info such as pod, authorized user etc.
    return a tuple of strings
    '''
    pod_slug = panther_base_helpers.deep_get(event, 'protoPayload', 'resourceName')
    # core/v1/namespaces/<namespace>/pods/<pod-id>/<action>
    _, _, _, namespace, _, pod, _ = pod_slug.split('/') 
    principal, project_id, caller_ip, user_agent, method_name = get_info(event)
    
    return principal, project_id, pod, caller_ip, user_agent, namespace


def gcp_flow_get_info(event):
    src_ip = panther_base_helpers.deep_get(event, 'jsonPayload', 'connection', 'src_ip')
    dest_ip = panther_base_helpers.deep_get(event, 'jsonPayload', 'connection', 'dest_ip')
    src_port = panther_base_helpers.deep_get(event, 'jsonPayload', 'connection', 'src_port')
    dest_port = panther_base_helpers.deep_get(event, 'jsonPayload', 'connection', 'dest_port')
    protocol = panther_base_helpers.deep_get(event, 'jsonPayload', 'connection', 'protocol')
    bytes_sent = panther_base_helpers.deep_get(event, 'jsonPayload', 'bytes_sent')
    reporter = panther_base_helpers.deep_get(event, 'jsonPayload', 'reporter')
    return src_ip, dest_ip, src_port, dest_port, protocol, bytes_sent, reporter