# Generated with the AWS CLI with the following command:
#   aws elbv2 describe-ssl-policies --query 'SslPolicies[?SslProtocols==[`TLSv1.2`]].Name'
TLS_1_2_POLICIES = {
    'ELBSecurityPolicy-TLS-1-2-2017-01',
    'ELBSecurityPolicy-TLS-1-2-Ext-2018-06',
    'ELBSecurityPolicy-FS-1-2-Res-2019-08', 'ELBSecurityPolicy-FS-1-2-2019-08'
}


def policy(resource):
    # Ignore load balancers that aren't serving internet traffic
    if resource['Scheme'] == 'internal':
        return True

    return (len(resource['Listeners']) >= 1 and all([
        policy in TLS_1_2_POLICIES for policy in resource['SSLPolicies'].keys()
    ]))
