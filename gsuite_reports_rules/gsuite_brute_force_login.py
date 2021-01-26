from panther_base_helpers import gsuite_details_lookup as details_lookup
from panther_base_helpers import deep_get
from panther_oss_helpers import evaluate_threshold

# TODO change to native thresholding once support is added
# tentatively slated for 1.7
THRESH = 10
THRESH_TTL = 600  # 10 minutes


def rule(event):
    # Filter events
    if deep_get(event, 'id', 'applicationName') != 'login':
        return False

    # Pattern match this event to the recon actions
    details = details_lookup('login', ['login_failure'], event)
    return bool(details) and evaluate_threshold(
        '{}-GSuiteLoginFailedCounter'.format(
            deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')),
        THRESH,
        THRESH_TTL,
    )


def title(event):
    return 'User [{}] exceeded the failed logins threshold'.format(
        deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>'))
