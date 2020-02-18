def rule(event):
    return 0.1 <= float(event.get('severity', 0)) <= 3.9
