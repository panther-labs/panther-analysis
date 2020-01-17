def policy(event):
    return event['BackupRetentionPeriod'] != 0
