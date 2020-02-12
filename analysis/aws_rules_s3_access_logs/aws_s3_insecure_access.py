def rule(event):
    return 'cipherSuite' not in event or 'tlsVersion' not in event
