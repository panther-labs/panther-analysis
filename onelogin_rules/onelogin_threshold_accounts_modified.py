from panther_oss_helpers import evaluate_threshold  # pylint: disable=import-error

THRESH = 15
THRESH_TTL = 600  # 10 minutes


def rule(event):

    # filter events; event type 11 is an actor_user changed user password
    if event.get('event_type_id') != 11:
        return False

    # keep track of how many users have had their password modified
    # by an actor user within the time window defined by THRESH_TTL
    return (evaluate_threshold(
        '{}-OneLoginUserAccountModified'.format(event.get('actor_user_id')),
        THRESH,
        THRESH_TTL,
    ))


def title(event):
    return 'User [{}] has exceeded the user account password change threshold'.format(
        event.get('actor_user_name'))
