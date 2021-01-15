from panther_base_helpers import deep_get


def policy(resource):
    for encryption_rule in resource['EncryptionRules'] or []:
        if encryption_rule.get('ApplyServerSideEncryptionByDefault', False):
            return deep_get(encryption_rule,
                            'ApplyServerSideEncryptionByDefault',
                            'SSEAlgorithm') is not None

    return False
