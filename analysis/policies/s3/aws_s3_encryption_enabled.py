def policy(resource):
    for encryption_rule in resource['EncryptionRules'] or []:
        if encryption_rule.get('ApplyServerSideEncryptionByDefault', False):
            return encryption_rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] is not None

    return False
