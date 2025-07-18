import re


def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "iam.amazonaws.com",
            event.deep_get("eventName", default="") == "PutUserPolicy",
            "S3 Browser" in event.deep_get("userAgent", default=""),
            re.match(
                r"^.*\"arn:aws:s3:::<YOUR-BUCKET-NAME>/.*\".*$",
                event.deep_get("requestParameters", default=""),
            ),
            '"s3:GetObject"' in event.deep_get("requestParameters", default=""),
            '"Allow"' in event.deep_get("requestParameters", default=""),
        ]
    ):
        return True
    return False
