def policy(resource):
    return any((resource["PublicAccessBlockConfiguration"] or {}).values())
