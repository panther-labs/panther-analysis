def rule(_) -> bool:
    """Always return True since the query already filtered for violations"""
    return True


def title(event) -> str:
    user_arn = event.get("user_arn", "unknown")
    bucket_name = event.get("bucket_name", "unknown")
    total_mb = round(event.get("total_bytes_downloaded", 0) / (1024 * 1024), 2)

    return f"Large S3 download detected: {user_arn} downloaded {total_mb}MB from {bucket_name}"


def alert_context(event) -> dict:
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
