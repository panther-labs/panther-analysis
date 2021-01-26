def policy(event):
    return event.get('BackupRetentionPeriod') != 0
