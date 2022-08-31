from panther_base_helpers import aws_rule_context

# A list of buckets where authenticated access is expected
AUTH_BUCKETS = {"example-bucket"}


def rule(event):
    return event.get("bucket") in AUTH_BUCKETS and not event.get("requester")


def title(event):
    return f"Unauthenticated access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET')}]"


def alert_context(event):
    return aws_rule_context(event)
