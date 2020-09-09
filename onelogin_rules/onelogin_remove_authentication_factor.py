def rule(event):

    # verify this is a auth factor being removed
    # event id 24 is otp device deregistration
    # event id 172 is a user deleted an authentication factor
    return event.get('event_type_id') == 24 or event.get('event_type_id') == 172


def dedup(event):
    return event.get('user_name')


def title(event):
    if event.get('event_type_id') == 172:
        return 'A user [{}] removed an authentication factor [{}]'.format(
            event.get('user_name'),
            event.get('authentication_factor_description',
                      'UNKNOWN_AUTH_FACTOR'))
    return 'A user [{}] deactivated an otp device [{}]'.format(
        event.get('user_name'),
        event.get('otp_device_name', 'UNKNOWN_OTP_DEVICE'))
