def rule(event):
    return event.deep_get('event', default="") == "Incorrect password"

def title(event):
    user = event.get('username')
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will act as deduplication string.
    return f'Password injection attack done by [{user}]'

# def dedup(event):
    #  (Optional) Return a string which will be used to deduplicate similar alerts.
    # return ''

# def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the alert sent to the SNS/SQS/Webhook destination
    # return {'key':'value'}