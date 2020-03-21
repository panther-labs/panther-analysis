def rule(event):
    return 7.0 <= float(event.get('severity', 0)) <= 8.9
