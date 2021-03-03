import botocore.exceptions
from datetime import datetime, timedelta
from json import dumps, loads
from panther_base_helpers import deep_get
from panther_oss_helpers import get_string_set, put_string_set
import pdb

# Note: Resource info may only come in once daily, this should be a sufficient upper bound for
#       timeouts while avoiding false-positives - reasonably set arbitrarily but might need tweaking
TIMEOUT_INTERVAL = timedelta(days=1, hours=2)
AWS_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PANTHER_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEFAULT_TIME = "0001-01-01T00:00:00Z"


def policy(resource):
    """Checks on a per-account basis if there is a global resource recorder configured.
    Rather than checking if an individual resource is compliant, this detection checks whether or not
    any observed AWS.Config.Recorder resources is compliant.

    TODO: Once Detection Pipelines are merged, implement downgraded (INFO) case for multiple
          global resource recorders.
    """
    # pdb.set_trace()
    # Determine whether or not the current resource records global resources
    resource_records_global_resources = bool(
        deep_get(resource, "RecordingGroup", "IncludeGlobalResourceTypes")
        and deep_get(resource, "Status", "Recording")
    )

    # Generate a unique cache key for each account
    account_key = gen_key(resource)
    # Retrieve the prior account recorder info from the cache, if any
    try:
        recorder_config = get_string_set(account_key)
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'ResourceNotFoundException':
            recorder_config = {}
        else:
            raise error

    print(recorder_config)

    # If this is the first time running, store and return early
    if not recorder_config:
        store_config_info(account_key, None, resource, resource_records_global_resources)
        return True

    # Load global recorder config, if any
    record = loads(recorder_config.pop())

    # Determine whether or not there exists a compliant recorder w.r.t TIMEOUT_INTERVAL
    existing_valid_recorder = not evaluate_timed_out(
        record.get("last_validated_timestamp", DEFAULT_TIME)
    )

    # Update the config
    store_config_info(account_key, record, resource, resource_records_global_resources)

    # Compliant if resource is compliant or prv. seen resource is compliant in TIMEOUT_INTERVAL
    if existing_valid_recorder or resource_records_global_resources:
        return True

    return False


def gen_key(resource):
    return f"AWS.Config.Recorder{resource.get('AccountId', '<UNKNOWN_ACCOUNT>')}"


def evaluate_timed_out(timestamp: str) -> bool:
    """Evaluates whether or not timestamp timed out.

    :param timestamp: Timestamp w/ format AWS_TIME_FORMAT
    :return: True if timed out; False if current time is within the TIMEOUT_INTERVAL.
    """
    if timestamp is None:
        return True

    ts = safely_convert_timestamp_to_datetime(timestamp)
    if not ts or ts == DEFAULT_TIME:
        return True
    return datetime.now() > (ts + TIMEOUT_INTERVAL)


def safely_convert_timestamp_to_datetime(timestamp):
    try:
        ts = datetime.strptime(timestamp, AWS_TIME_FORMAT)
    except ValueError:
        ts = datetime.strptime(timestamp, PANTHER_TIME_FORMAT)
    except TypeError:
        return None

    return ts


def safely_convert_datetime_to_string(date: datetime):
    return date.isoformat(timespec='milliseconds') + 'Z'


def store_config_info(key: str, resource, prv_config: dict, resource_is_compliant: bool) -> None:
    # If resource is compliant, just write it as such
    if resource_is_compliant:
        valid_asset = resource.get("ResourceId", "<UNKNOWN_RESOURCE_ID>")
        timestamp = deep_get(resource, "Status", "LastStatusChangeTime")
        valid_datetime = safely_convert_timestamp_to_datetime(timestamp)
        if not valid_datetime:
            valid_timestamp = safely_convert_datetime_to_string(datetime.now())
        else:
            valid_timestamp = safely_convert_datetime_to_string(valid_datetime)
    else:
        # Otherwise, if it's not and we need to initialize the config
        if not prv_config:
            valid_asset = ""
            valid_timestamp = DEFAULT_TIME
        # Overwrite based on previous config
        else:
            valid_asset = prv_config.get("last_validated_asset")
            valid_timestamp = prv_config.get("last_validated_timestamp")
    # Map accountId to "meta resource" config
    put_string_set(
        key,
        [
            dumps(
                {
                    "last_validated_asset": valid_asset,
                    "last_validated_timestamp": valid_timestamp,
                    # Unsure about this last_check_timestamp...
                    "last_check_timestamp": safely_convert_datetime_to_string(datetime.now())
                }
            )
        ],
    )
