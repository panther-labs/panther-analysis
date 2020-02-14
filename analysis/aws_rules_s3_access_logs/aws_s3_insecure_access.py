def rule(event):
    return 'ciphersuite' not in event or 'tlsVersion' not in event
