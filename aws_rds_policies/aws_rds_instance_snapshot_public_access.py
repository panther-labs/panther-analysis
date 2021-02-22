# When a single item is loaded from json, it is loaded as a single item
# When a list of items is loaded from json, it is loaded as a list of that item
# When we want to iterate over something that could be a single item or a list
# of items we can use listify and just continue as if it's always a list
def listify(maybe_list):
    return [maybe_list] if not isinstance(maybe_list, list) else maybe_list


def policy(resource):
    # Check if this instance has snapshots
    if resource["SnapshotAttributes"] is None:
        return True

    # Check that no snapshots are able to be restored by all (i.e. are public)
    for snapshot_attrs in resource["SnapshotAttributes"]:
        for snapshot_attr in snapshot_attrs["DBSnapshotAttributes"]:
            if (
                snapshot_attr["AttributeName"] == "restore"
                and snapshot_attr["AttributeValues"] is not None
                and "all" in listify(snapshot_attr["AttributeValues"])
            ):
                return False

    return True
