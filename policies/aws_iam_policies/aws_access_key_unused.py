import datetime

from panther_oss_helpers import resolve_timestamp_string

TIMEOUT_DAYS = datetime.timedelta(days=90)
DEFAULT_TIME = "0001-01-01T00:00:00Z"


def aged_out(timestamp):
    if not timestamp:
        return False
    datetime_ts = resolve_timestamp_string(timestamp)

    if not datetime_ts:
        return True
    return (datetime.datetime.now() - datetime_ts) > TIMEOUT_DAYS


def policy(resource):
    # If a user is less than 4 hours old, it may not have a credential report generated yet.
    # It will be re-scanned periodically until a credential report is found, at which point this
    # policy will be properly evaluated.
    report = resource.get("CredentialReport")
    if not report:
        return True

    if report.get("AccessKey1Active"):
        if report.get("AccessKey1LastUsedDate") != DEFAULT_TIME and aged_out(
            report.get("AccessKey1LastUsedDate")
        ):
            return False
        if report.get("AccessKey1LastUsedDate") == DEFAULT_TIME and aged_out(
            report.get("AccessKey1LastRotated")
        ):
            return False
    if report.get("AccessKey2Active"):
        if report.get("AccessKey2LastUsedDate") != DEFAULT_TIME and aged_out(
            report.get("AccessKey2LastUsedDate")
        ):
            return False
        if report.get("AccessKey2LastUsedDate") == DEFAULT_TIME and aged_out(
            report.get("AccessKey2LastRotated")
        ):
            return False

    return True
