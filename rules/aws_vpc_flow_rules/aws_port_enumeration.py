import ast
import json
from datetime import datetime, timedelta

from panther_oss_helpers import get_string_set, put_string_set


def get_key(event):
    return __name__ + ":" + str(event.get("srcaddr"))


def rule(event):
    # VPC Flow logs have events where not all info are present
    if (
        not event.get("srcaddr")
        or not event.get("dstaddr")
        or not event.get("srcport")
        or not event.get("dstport")
    ):
        return False

    key = get_key(event)
    accessed_ports = get_string_set(key)

    # Mocking returns string - For testing only
    if isinstance(accessed_ports, str):
        if accessed_ports:
            accessed_ports = ast.literal_eval(accessed_ports)
        else:
            accessed_ports = set()
    ###

    if accessed_ports:
        accessed_ports = json.loads(accessed_ports.pop())
    else:
        accessed_ports = {}

    dstaddr = event.get("dstaddr")
    dstport = event.get("dstport")

    new_accessed_ports = accessed_ports.get(dstaddr, [])
    new_accessed_ports.append(dstport)
    new_accessed_ports = list(set(new_accessed_ports))

    accessed_ports[dstaddr] = new_accessed_ports

    put_string_set(
        key,
        json.dumps(accessed_ports),
        epoch_seconds=str((datetime.now() + timedelta(days=1)).timestamp()),
    )

    if len(accessed_ports.get(dstaddr, [])) >= 5:
        return True
    return False


def title(event):
    return f"[{event.get('srcaddr')}] has scanned > 5 ports on [{event.get('dstaddr')}]"


def dedup(event):
    return f"{event.get('srcaddr')}"
