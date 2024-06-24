def rule(event):
    # List of suspicious API events
    # NOTE: There may be more API events that's not listed
    suspicious_api_events = [
        "HeadObject",
        "GetObject",
        "GetObjectAcl",
        "GetObjectAttributes",
        "GetObjectLegalHold",
        "GetObjectLockConfiguration",
        "GetObjectRetention",
        "GetObjectTagging",
        "GetObjectTorrent",
        "PutObject",
        "PutObjectAcl",
        "PutObjectLegalHold",
        "PutObjectLockConfiguration",
        "PutObjectRetention",
        "PutObjectTagging",
        "SelectObjectContent",
        "DeleteObject",
        "DeleteObjects",
        "DeleteObjectTagging",
    ]

    # Return True if the API value is in the list of suspicious API events
    if event["GeneratorId"] == "s3.amazonaws.com":
        # Extract the API value from the event
        api_value = event["Action"]["AwsApiCallAction"]["Api"]

        return api_value in suspicious_api_events
    return False


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    # If no 'dedup' function is defined, the return value of this method will act as dedup string.

    # NOTE: Not sure if the offending actor Id will always be in the 0th index of Resources
    # It's possible to just return the Title as a whole string
    secret = event["Resources"][0]["Id"]
    return f"Suspicious activity detected accessing private decoy S3 bucket {secret}"
