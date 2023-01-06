import ast
from datetime import datetime, timedelta
from statistics import mean
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration

# If event.get('num_logs') / AVERAGE_COUNT > ANOMALY_THRESHOLD, detection fires
ANOMALY_THRESHOLD = 10

# MAX_LEDGER_COUNT enforces a cap on list items for the rolling ledger
# If len(COUNT_LEDGER) == MAX_LEDGER_COUNT, the oldest list item is purged
MAX_LEDGER_COUNT = 15

COUNT_LEDGER = None
AVERAGE_COUNT = None

def rule(event):
    global COUNT_LEDGER
    global AVERAGE_COUNT

    # Generate the DynamoDB key
    key = get_key(event)

    num_logs = event.get("num_logs", 0)

    # Get the count ledger from DynamoDB (if there is one)
    # Example: [10, 15, 200, 20, 10....]
    COUNT_LEDGER = get_count_ledger(key)

    # Handle Unit Tests with mock overrides
    if isinstance(COUNT_LEDGER, str):
        COUNT_LEDGER = {'[40, 10, 20]'}

    # If there is no count ledger, we start one and store it in DynamoDB
    # Example:
    #       num_logs = 10
    #       Therefore, COUNT_LEDGER = [10]
    if not COUNT_LEDGER:
        new_ledger = [num_logs]
        put_string_set(key, [str(new_ledger)])
        set_key_expiration(key, str((datetime.now() + timedelta(minutes=30)).timestamp()))
        return False

    # Since DynamoDB returns a string set, we need to deserialize into a list using ast.literal
    COUNT_LEDGER = ast.literal_eval(COUNT_LEDGER.pop())

    # Calculate an average of all previous log counts
    AVERAGE_COUNT = mean(COUNT_LEDGER)

    # If list length exceeds MAX_LEDGER_COUNT, then prune first item on the list
    if len(COUNT_LEDGER) == MAX_LEDGER_COUNT:
        COUNT_LEDGER.pop(0)

    # Append the current count to the list (after the average is calculated)
    COUNT_LEDGER.append(num_logs)

    # Store the updated count ledger in DynamoDB
    put_string_set(key, [str(COUNT_LEDGER)])

    return num_logs / AVERAGE_COUNT >= ANOMALY_THRESHOLD


def get_count_ledger(key):
    return get_string_set(key)


def get_key(event):
    return str(event.get("p_log_type")) + __name__


def title(event):
    return (f"Anomoly detected in [{event.get('p_log_type')}] - "
        "Event volume average has exceeded threshold")


def alert_context(event):
    context = {}
    context['Log Type'] = event.get('p_log_type')
    context['Count Ledger'] = COUNT_LEDGER
    context['Average'] = AVERAGE_COUNT

    return context
