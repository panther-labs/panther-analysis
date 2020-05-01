def policy(resource):
    return (not resource['CredentialReport']['AccessKey1Active'] and
            not resource['CredentialReport']['AccessKey2Active'])
