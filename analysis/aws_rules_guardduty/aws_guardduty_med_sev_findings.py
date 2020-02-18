def rule(event):
    return 4.0 <= float(event.get('severity', 0)) <= 6.9
