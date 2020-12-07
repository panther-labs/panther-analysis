from panther_oss_helpers import build_client

def policy(resource):    
    client = build_client(resource)
    results = client.describe_network_interfaces(Filters=[{'Name' : 'group-id', 'Values' : [resource['Id']]}])
    if results['NetworkInterfaces']:
        return True
    else:
        return False

