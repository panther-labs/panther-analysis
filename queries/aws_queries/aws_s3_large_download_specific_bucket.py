from panther_aws_helpers import aws_rule_context
from panther_core import PantherEvent


def rule(_) -> bool:
    """Always return True since the query already filtered for violations"""
    return True


def title(event: PantherEvent) -> str:
    user_arn = event.get("user_arn", "unknown")
    bucket_name = event.get("bucket_name", "unknown")
    total_mb = round(event.get("total_bytes_downloaded", 0) / (1024 * 1024), 2)

    return f"Large S3 download detected: {user_arn} downloaded {total_mb}MB from {bucket_name}"


def severity(event: PantherEvent) -> str:
    total_bytes = event.get("total_bytes_downloaded", 0)
    total_mb = total_bytes / (1024 * 1024)

    if total_mb >= 1000:  # 1GB+
        return "CRITICAL"
    elif total_mb >= 500:  # 500MB+
        return "HIGH"
    else:  # 100MB+
        return "MEDIUM"


def alert_context(event: PantherEvent) -> dict:
    total_bytes = event.get("total_bytes_downloaded", 0)
    total_mb = round(total_bytes / (1024 * 1024), 2)

    return {
        "user_arn": event.get("user_arn"),
        "user_name": event.get("user_name"),
        "bucket_name": event.get("bucket_name"),
        "source_ip": event.get("source_ip"),
        "user_agent": event.get("user_agent"),
        "total_bytes_downloaded": total_bytes,
        "total_mb_downloaded": total_mb,
        "object_count": event.get("object_count"),
        "first_download_time": event.get("first_download_time"),
        "last_download_time": event.get("last_download_time"),
        "sample_objects": event.get("sample_objects", [])[:10],  # Show first 10 objects
    }
