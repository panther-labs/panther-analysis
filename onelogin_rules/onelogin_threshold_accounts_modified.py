from panther_oss_helpers import evaluate_threshold  # pylint: disable=import-error


def rule(event):

    # filter events; event type 11 is an actor_user changed user password
    return event.get('event_type_id') == 11


def dedup(event):
    # The modified user's user_name
    return event.get('user_name')


def title(event):
    return 'User [{}] has exceeded the user account password change threshold'.format(
        event.get('actor_user_name'))
