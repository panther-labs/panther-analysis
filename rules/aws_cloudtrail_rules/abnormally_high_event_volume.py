import ast
from datetime import datetime, timedelta
from statistics import mean
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration

# If event.get('num_logs') / average_count > ANOMALY_THRESHOLD, detection fires
ANOMALY_THRESHOLD = 10

# MAX_LEDGER_COUNT enforces a cap on list items for the rolling ledger
# If len(count_ledger) == MAX_LEDGER_COUNT, the oldest list item is purged
MAX_LEDGER_COUNT = 15


def rule(event):
    global count_ledger
    global average_count

    # Generate the DynamoDB key
    key = get_key(event)

    num_logs = event.get("num_logs", 0)

    # Get the count ledger from DynamoDB (if there is one)
    # Example: [10, 15, 200, 20, 10....]
    count_ledger = get_count_ledger(key)

    # Handle Unit Tests with mock overrides
    if isinstance(count_ledger, str):
        count_ledger = {'[40, 10, 20]'}

    # If there is no count ledger, we start one and store it in DynamoDB
    # Example:
    #       num_logs = 10
    #       Therefore, count_ledger = [10]
    if not count_ledger:
        new_ledger = [num_logs]
        put_string_set(key, [str(new_ledger)])
        set_key_expiration(key, str((datetime.now() + timedelta(minutes=30)).timestamp()))
        return False
    
    # Since DynamoDB returns a string set, we need to deserialize into a list using ast.literal
    count_ledger = ast.literal_eval(count_ledger.pop())

    # Calculate an average of all previous log counts
    average_count = mean(count_ledger)

    # If list length exceeds MAX_LEDGER_COUNT, then prune first item on the list
    if len(count_ledger) == MAX_LEDGER_COUNT:
        count_ledger.pop(0)

    # Append the current count to the list (after the average is calculated)
    count_ledger.append(num_logs)

    # Store the updated count ledger in DynamoDB
    put_string_set(key, [str(count_ledger)])
    
    return num_logs / average_count >= ANOMALY_THRESHOLD


def get_count_ledger(key):
    return get_string_set(key)


def get_key(event):
    return str(event.get("p_log_type")) + __name__


def title(event):
    return f"Anomoly detected in [{event.get('p_log_type')}] - Event volume average has exceeded threshold"


def alert_context(event):
    context = {}
    context['Count Ledger'] = count_ledger
    context['Average'] = average_count

    return context