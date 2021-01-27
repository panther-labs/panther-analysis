from panther_base_helpers import deep_get, gsuite_details_lookup as details_lookup
from panther_oss_helpers import evaluate_threshold
'''
SELECT *
FROM panther_logs.public.gsuite_reports
WHERE id:applicationName = 'login'
AND events[0]:name = 'login_failure' LIMIT 10;
'''

# TODO change to native thresholding once support is added
# tentatively slated for 1.7
THRESH = 10
THRESH_TTL = 600  # 10 minutes


def rule(event):
    # Filter login events
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
    return 'Brute force login suspected for user [{}]'.format(
        deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>'))
