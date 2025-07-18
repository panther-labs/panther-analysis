def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "s3.amazonaws.com",
            event.deep_get("eventName", default="")
            in [
                "PutBucketLogging",
                "PutBucketWebsite",
                "PutEncryptionConfiguration",
                "PutLifecycleConfiguration",
                "PutReplicationConfiguration",
                "ReplicateObject",
                "RestoreObject",
            ],
        ]
    ):
        return True
    return False
