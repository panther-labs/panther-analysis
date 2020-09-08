from panther_oss_helpers import evaluate_threshold  # pylint: disable=import-error

THRESH = 15
THRESH_TTL = 600  # 10 minutes


def rule(event):

    # filter events; event type 17 is a user deleted
    if event.get('event_type_id') != 17:
        return False

    # keep track of how many users are being deleted
    # by an actor user within the time window defined by THRESH_TTL
    return (evaluate_threshold(
        '{}-OneLoginUserAccountDeleted'.format(event.get('actor_user_id')),
        THRESH,
        THRESH_TTL,
    ))


def title(event):
    return 'User [{}] has exceeded the user account deletion threshold'.format(
        event.get('actor_user_name'))
