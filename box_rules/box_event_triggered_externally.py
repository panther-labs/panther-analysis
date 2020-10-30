DOMAINS = {
    '@example.com',
}


def rule(event):
    # Check that all events are triggered by internal users
    if event.get('event_type') not in ('FAILED_LOGIN', 'SHIELD_ALERT'):
        user = event.get('created_by', {})
        if user.get('id', '') == '2':
            return True
        return user.get('login') and not any(
            user.get('login').endswith(x) for x in DOMAINS)
    return False


def title(event):
    message = ('External user [{}] triggered a box event.')
    return message.format(
        event.get('created_by', {}).get('login', '<UNKNOWN_USER>'))
