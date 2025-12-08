import re

from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

# Common ransomware note filename patterns
RANSOM_NOTE_PATTERNS = [
    # Explicit ransomware-related terms
    # RANSOM_NOTE.txt, PAYMENT_INFO.html
    r"(?i)(ransom|payment)[_-]?(note|info|instructions?).*\.(txt|html?)$",
    # Decrypt/restore with specific action words
    # HOW_TO_DECRYPT_FILES.txt
    r"(?i)how[_-]?to[_-]?(decrypt|restore|recover)[_-]?(your[_-]?)?files.*\.(txt|html?)$",
    # DECRYPT_INSTRUCTIONS.txt
    r"(?i)decrypt[_-]?(instructions?|guide|info|your[_-]?files).*\.(txt|html?)$",
    # RESTORE_INSTRUCTIONS.txt
    r"(?i)restore[_-]?(instructions?|guide|info|your[_-]?files).*\.(txt|html?)$",
    # RECOVERY_INSTRUCTIONS.txt
    r"(?i)recovery[_-]?(instructions?|key|guide).*\.(txt|html?)$",
    # Files encrypted/locked messages
    # FILES_ENCRYPTED.txt, ALL_FILES_HAVE_BEEN_ENCRYPTED.txt
    r"(?i)(all[_-]?)?files?[_-]?(have[_-]?been[_-]?)?(encrypted|locked).*\.(txt|html?)$",
    # YOUR_FILES_ARE_ENCRYPTED.txt
    r"(?i)your[_-]?files?[_-]?(are|have[_-]?been)[_-]?(encrypted|locked).*\.(txt|html?)$",
    # DATA_ENCRYPTED.txt
    r"(?i)data[_-]?(has[_-]?been[_-]?)?(encrypted|locked).*\.(txt|html?)$",
    # Unlock-related (common in ransomware)
    # UNLOCK_INSTRUCTIONS.txt
    r"(?i)unlock[_-]?(instructions?|guide|your[_-]?files).*\.(txt|html?)$",
    # Help decrypt/restore (specific to ransomware)
    # HELP_DECRYPT_YOUR_FILES.txt
    r"(?i)help[_-]?(restore|decrypt|recover)[_-]?(your[_-]?)?files.*\.(txt|html?)$",
]

COMPILED_PATTERNS = [re.compile(pattern) for pattern in RANSOM_NOTE_PATTERNS]


def extract_filename(event):
    key = event.deep_get("requestParameters", "key", default="")
    if not key:
        resources = event.get("resources", [])
        for resource in resources:
            if resource.get("type") == "AWS::S3::Object":
                arn = resource.get("arn", "")
                # Extract key from ARN (format: arn:aws:s3:::bucket/key)
                if "/" in arn:
                    key = arn.split("/", 1)[1]
                    break

    filename = key.split("/")[-1] if "/" in key else key
    return filename


def rule(event):

    if event.get("eventName") != "PutObject" or not aws_cloudtrail_success(event):
        return False

    filename = extract_filename(event)

    # Check if filename matches any ransomware note pattern
    return any(pattern.match(filename) for pattern in COMPILED_PATTERNS)


def title(event):
    bucket = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN_BUCKET>")
    filename = extract_filename(event)

    return (
        f"[AWS.CloudTrail] Potential ransomware note uploaded to S3: "
        f"[{filename}] in bucket [{bucket}] by user [{event.udm('actor_user')}]"
    )


def alert_context(event):
    context = aws_rule_context(event)
    key = event.deep_get("requestParameters", "key", default="<UNKNOWN_KEY>")
    context["bucketName"] = event.deep_get(
        "requestParameters", "bucketName", default="<UNKNOWN_BUCKET>"
    )
    context["objectKey"] = key
    context["filename"] = extract_filename(event)
    return context
