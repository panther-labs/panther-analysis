import datetime

TIMEOUT_DAYS = datetime.timedelta(days=90)
AWS_TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEFAULT_TIME = '0001-01-01T00:00:00Z'


def aged_out(timestamp):
    datetime_ts = datetime.datetime.strptime(timestamp, AWS_TIMESTAMP_FORMAT)
    return (datetime.datetime.now() - datetime_ts) > TIMEOUT_DAYS


def policy(resource):
    # If a user is less than 4 hours old, it may not have a credential report generated yet.
    # It will be re-scanned periodically until a credential report is found, at which point this
    # policy will be properly evaluated.
    report = resource['CredentialReport']
    if not report:
        return True

    if report['AccessKey1Active']:
        if report['AccessKey1LastUsedDate'] != DEFAULT_TIME and aged_out(
                report['AccessKey1LastUsedDate']):
            return False
        if report['AccessKey1LastUsedDate'] == DEFAULT_TIME and aged_out(
                report['AccessKey1LastRotated']):
            return False
    if report['AccessKey2Active']:
        if report['AccessKey2LastUsedDate'] != DEFAULT_TIME and aged_out(
                report['AccessKey2LastUsedDate']):
            return False
        if report['AccessKey2LastUsedDate'] == DEFAULT_TIME and aged_out(
                report['AccessKey2LastRotated']):
            return False

    return True
