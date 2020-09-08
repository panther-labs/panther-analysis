from panther_oss_helpers import evaluate_threshold  # pylint: disable=import-error

# TODO change to native thresholding once support is added
THRESH = 10
THRESH_TTL = 600  # 10 minutes


def rule(event):

    # filter events; event type 6 is a failed authentication
    if event.get('event_type_id') != 6:
        return False

    # keep track of user authentication failures
    # using the same username can trigger a brute force alert
    if (evaluate_threshold(
            '{}-OneLoginFailedCounterUsername'.format(
                event.get('actor_user_id')),
            THRESH,
            THRESH_TTL,
    )):
        return True

    # failed logins originating from a single ip,
    # but not necessarily using the same username can trigger
    # a brute force alert (e.g. password spraying)
    if evaluate_threshold(
            '{}-OneLoginFailedCounterIpAddress'.format(event.get('ipaddr')),
            THRESH,
            THRESH_TTL,
    ):
        return True

    # TODO: what is acceptable number of failures in 10 minutes for entire
    # org? The same threshold as username/ip checks?
    # check password spraying from a wide range of ip addresses
    #return evaluate_threshold(
    #    'OneLoginFailedCounterTotal',
    #    THRESH,
    #    THRESH_TTL,
    #)
    return False


def dedup(event):
    return event.get('actor_user_name')


def title(event):
    return 'User [{}] or IP [{}] has exceeded the failed logins threshold'.format(
        event.get('actor_user_name'), event.get('ipaddr'))
