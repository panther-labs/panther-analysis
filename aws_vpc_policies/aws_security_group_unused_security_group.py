from panther_audit import build_client

def policy(resource):    
    client = build_client(resource, 'ec2', resource['Region'])
    results = client.describe_network_interfaces(Filters=[{'Name' : 'group-id', 'Values' : [resource['Id']]}])
    if results.get('NetworkInterfaces'):
        return True
    else:
        return False
