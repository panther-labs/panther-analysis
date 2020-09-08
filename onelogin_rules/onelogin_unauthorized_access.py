from panther_oss_helpers import evaluate_threshold  # pylint: disable=import-error

# TODO change to native thresholding once support is added
THRESH = 10
THRESH_TTL = 600  # 10 minutes


def rule(event):

    # filter events; event type 90 is an unauthorized applicaiton access event id
    if event.get('event_type_id') != 90 or not event.get('user_id'):
        return False

    # keep track of user application unauthorized access attempts
    return (evaluate_threshold(
        '{}-OneLoginUnauhtorizedAccessUsername'.format(event.get('user_id')),
        THRESH,
        THRESH_TTL,
    ))


def title(event):
    return 'User [{}] has exceeded the unauthorized application access attempt threshold'.format(
        event.get('user_name', '<UNKNOWN_USER>'))
