from panther_base_helpers import aws_rule_context, pattern_match


def rule(event):
    return pattern_match(event.get("operation", ""), "REST.*.OBJECT") and (
        not event.get("ciphersuite") or not event.get("tlsVersion")
    )


def title(event):
    return f"Insecure access to S3 Bucket [{event.get('bucket', '<UNKNOWN_BUCKET>')}]"


def alert_context(event):
    return aws_rule_context(event)
