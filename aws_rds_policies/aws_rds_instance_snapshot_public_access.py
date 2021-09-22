from panther_oss_helpers import listify


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
