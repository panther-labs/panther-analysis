from json import dumps, loads
from datetime import datetime
from statistics import mean
from panther_oss_helpers import get_string_set, put_string_set

# AVERAGE_THRESHOLD defines the factor by which the log count must exceed the rolling_ledger average
AVERAGE_THRESHOLD = 10

# ROLLING_LEDGER_SIZE defines the length of the rolling_ledger list
ROLLING_LEDGER_SIZE = 30


def rule(event):
    # Generate the DynamoDB key
    key = get_key(event)

    # Get the current number of events, store in num_logs
    num_logs = event.get("num_logs", 0)

    # Get the count ledger from DynamoDB (if there is one)
    count_ledger = get_count_ledger(key)

    # If there is no count_ledger, we start one and store it in DynamoDB
    if not count_ledger:
        new_ledger = {
            "rolling_ledger": [num_logs],
            "highest_counts": {str(datetime.now()): num_logs},
        }

        put_count_ledger(key, new_ledger)
        return False

    # Calculate an average of all previous log counts
    average_count = mean(count_ledger["rolling_ledger"])

    # If list length exceeds ROLLING_LEDGER_SIZE, then prune first item on the list
    if len(count_ledger["rolling_ledger"]) == ROLLING_LEDGER_SIZE:
        count_ledger["rolling_ledger"].pop(0)

    # Append the current count to the list (after the average is calculated)
    count_ledger["rolling_ledger"].append(num_logs)

    # Find the highest count in the ledger
    highest_count = max(count_ledger["highest_counts"].values())

    # Assume there is not a new
    new_highest_count = False

    # Store a new highest count if found
    if num_logs >= highest_count:
        count_ledger["highest_counts"][str(datetime.now())] = num_logs
        new_highest_count = True

    # Store the updated count ledger in DynamoDB
    put_count_ledger(key, count_ledger)

    # Determine if num_logs exceeds average_count by a factor of AVERAGE_THRESHOLD or greater
    crossed_average_threshold = num_logs / average_count >= AVERAGE_THRESHOLD

    # Alert only when AVERAGE_THRESHOLD is crossed && there is new highest_count value
    return crossed_average_threshold and new_highest_count


def title(event):
    return f"Abnormally high event volume detected in [{event.get('p_log_type')}]"


def alert_context(event):
    key = get_key(event)
    count_ledger = get_count_ledger(key)

    context = {}
    context["Log Type"] = event.get("p_log_type")
    context["Average Threshold"] = AVERAGE_THRESHOLD
    context["Rolling Ledger"] = count_ledger["rolling_ledger"]
    context["Highest Counts"] = count_ledger["highest_counts"]
    context["Rolling Ledger Average"] = mean(count_ledger["rolling_ledger"])

    # If an alert has fired, we reset the highest_counts dict
    count_ledger["highest_counts"] = {}
    put_count_ledger(key, count_ledger)

    return context


def put_count_ledger(key, count_ledger):
    put_string_set(key, [dumps(count_ledger)])


def get_count_ledger(key):
    count_ledger = get_string_set(key)

    # Handle Unit Tests with mock overrides
    if isinstance(count_ledger, str):
        return {"rolling_ledger": [40, 10, 20], "highest_counts": {str(datetime.now()): 40}}

    # Since DynamoDB returns a string set, we need to deserialize into a dict
    if count_ledger:
        return loads(count_ledger.pop())

    return None


def get_key(event):
    return str(event.get("p_log_type")) + __name__
