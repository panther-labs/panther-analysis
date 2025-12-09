from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):

    if event.get("eventName") != "CopyObject" or not aws_cloudtrail_success(event):
        return False

    kms_key_arn = event.deep_get(
        "requestParameters",
        "x-amz-server-side-encryption-aws-kms-key-id",
        default="<UNKNOWN_KEY_ID>",
    )

    if kms_key_arn.startswith("arn:aws:kms:"):
        # Extract account ID from KMS key ARN (format: arn:aws:kms:region:account:key/key-id)
        kms_parts = kms_key_arn.split(":")
        if len(kms_parts) >= 5:
            kms_account_id = kms_parts[4]
            bucket_account_id = event.get("recipientAccountId", "")

            # Alert on cross-account KMS key usage
            if kms_account_id != bucket_account_id:
                return True

    return False


def title(event):

    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"encrypted an object in bucket "
        f"[{event.deep_get('requestParameters', 'bucketName')}] "
        f"with a KMS key belonging to a different account ID "
        f"than the account owner ID"
    )


def alert_context(event):
    context = aws_rule_context(event)
    context["bucketName"] = event.deep_get(
        "requestParameters", "bucketName", default="<UNKNOWN_BUCKET>"
    )
    context["objectKey"] = event.deep_get("requestParameters", "key", default="<UNKNOWN_KEY>")

    kms_key_arn = event.deep_get(
        "requestParameters",
        "x-amz-server-side-encryption-aws-kms-key-id",
        default="<UNKNOWN_KEY_ARN>",
    )
    context["kmsKeyId"] = kms_key_arn

    # Add cross-account indicator
    if kms_key_arn:
        kms_parts = kms_key_arn.split(":")
        if len(kms_parts) >= 5:
            kms_account_id = kms_parts[4]
            bucket_account_id = event.get("recipientAccountId", "")
            context["isCrossAccountKms"] = kms_account_id != bucket_account_id
            context["kmsAccountId"] = kms_account_id
            context["bucketAccountId"] = bucket_account_id

    context["encryption"] = event.deep_get(
        "requestParameters", "x-amz-server-side-encryption", default="<UNKNOWN_ENCRYPTION>"
    )
    return context
