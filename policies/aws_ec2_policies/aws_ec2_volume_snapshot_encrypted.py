def policy(resource):
    for snapshot in resource["Snapshots"] or []:
        if snapshot["State"] != "completed":
            continue
        if not bool(snapshot["Encrypted"]):
            return False
    return True
