import panther_base_helpers

def get_info(event):
    fields = {
        'principal': 'protoPayload.authenticationInfo.principalEmail',
        'project_id': 'protoPayload.resource.labels.project_id',
        'caller_ip': 'protoPayload.requestMetadata.callerIP',
        'user_agent': 'protoPayload.requestMetadata.callerSuppliedUserAgent',
        'method_name': 'protoPayload.methodName',
    }
    return {
        name: panther_base_helpers.deep_get(event, *(path.split('.')))
        for name, path in fields
    }

def get_k8s_info(event):
    '''
    Get GCP K8s info such as pod, authorized user etc.
    return a tuple of strings
    '''
    pod_slug = panther_base_helpers.deep_get(event, 'protoPayload', 'resourceName')
    # core/v1/namespaces/<namespace>/pods/<pod-id>/<action>
    _, _, _, namespace, _, pod, _ = pod_slug.split('/')     
    return get_info(event) | {'namespace': namespace, 'pod': pod}

def get_gcp_flow_info(event):
    fields = {
        'src_ip': 'jsonPayload.connection.src_ip',
        'dest_ip': 'jsonPayload.connection.dest_ip',
        'src_port': 'jsonPayload.connection.src_port',
        'dest_port': 'jsonPayload.connection.dest_port',
        'protocol': 'jsonPayload.connection.protocol',
        'bytes_sent': 'jsonPayload.bytes_sent',
        'reporter': 'jsonPayload.reporter'
    }
    return {
        name: panther_base_helpers.deep_get(event, *(path.split('.')))
        for name, path in fields
    }
