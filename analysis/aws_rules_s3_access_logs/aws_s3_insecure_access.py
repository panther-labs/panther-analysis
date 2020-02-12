def rule(event):
    return event['cipherSuite'] == '-' or event['tlsVersion'] == '-'
