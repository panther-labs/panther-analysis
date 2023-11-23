from datetime import timedelta, datetime
from typing import Dict, Tuple

from panther_base_helpers import (
    golang_nanotime_to_python_datetime,
    panther_nanotime_to_python_datetime,
)

PANTHER_TIME_FORMAT = r"%Y-%m-%d %H:%M:%S.%f"
# Tune this to be some Greatest Common Denominator of session TTLs for your
# environment
MAXIMUM_NORMAL_VALIDITY_INTERVAL = timedelta(hours=12)
# To allow some time in between when a request is submitted and authorized
# vs when the certificate actually gets generated. In practice, this is much
# less than 5 seconds.
ISSUANCE_GRACE_PERIOD = timedelta(seconds=5)

# You can audit your logs in Panther to try and understand your role/validity
# patterns from a known-good period of access.
# A query example:
# ```sql
#  SELECT
#     cluster_name,
#     identity:roles,
#     DATEDIFF('HOUR', time, identity:expires) AS validity
#  FROM
#     panther_logs.public.gravitational_teleportaudit
#  WHERE
#     p_occurs_between('2023-09-01 00:00:00','2023-10-06 21:00:00Z')
#     AND event = 'cert.create'
#  GROUP BY cluster_name, identity:roles, validity
#  ORDER BY validity DESC
# ```

# A dictionary of:
#  cluster names: to a dictionary of:
#     role names: mapping to a tuple of:
#        ( maximum usual validity, expiration datetime for this rule )
CLUSTER_ROLE_MAX_VALIDITIES: Dict[str, Dict[str, Tuple[timedelta, datetime]]] = {
    # "teleport.example.com": {
    #     "example_role": (timedelta(hours=720), datetime(2023, 12, 01, 01, 02, 03)),
    #     "other_example_role": (timedelta(hours=720), datetime.max),
    # },
}


def rule(event):
    if not event.get("event") == "cert.create":
        return False
    max_validity = MAXIMUM_NORMAL_VALIDITY_INTERVAL + ISSUANCE_GRACE_PERIOD
    for role in event.deep_get("identity", "roles", default=[]):
        validity, expiration = CLUSTER_ROLE_MAX_VALIDITIES.get(event.get("cluster_name"), {}).get(
            role, (None, None)
        )
        if validity and expiration:
            # Ignore exceptions that have passed their expiry date
            if datetime.utcnow() < expiration:
                max_validity = max(max_validity, validity)
    return validity_interval(event) > max_validity


def validity_interval(event):
    event_time = panther_nanotime_to_python_datetime(event.get("time"))
    expires = golang_nanotime_to_python_datetime(event.deep_get("identity", "expires", default=None))
    if not event_time and expires:
        return False
    interval = expires - event_time
    return interval


def title(event):
    return (
        f"A Certificate for  [{event.get('identity', {}).get('user', '<Cert with no User!?>')}] "
        f"on [{event.get('cluster_name', '<UNKNOWN_CLUSTER>')}] "
        f"has been issued for an unusually long time: {validity_interval(event)!r} "
    )
