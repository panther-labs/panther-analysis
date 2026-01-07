def _parse_destination(destination):
    """Parse bucket and project from destination path.

    Returns tuple: (dest_bucket, dest_project)
    destination format: projects/PROJECT_ID/buckets/BUCKET_NAME/objects/...
    """
    dest_bucket = None
    dest_project = None

    if "buckets/" in destination and "objects/" in destination:
        try:
            dest_bucket = destination.split("buckets/")[1].split("/objects/")[0]
        except (IndexError, AttributeError):
            pass

    if "projects/" in destination and "buckets/" in destination:
        try:
            project = destination.split("projects/")[1].split("/buckets/")[0]
            dest_project = project if project != "_" else None
        except (IndexError, AttributeError):
            pass

    return dest_bucket, dest_project


def rule(event):

    if (
        event.deep_get("protoPayload", "methodName") != "storage.objects.get"
        or event.deep_get("protoPayload", "serviceName") != "storage.googleapis.com"
        or event.get("severity") == "ERROR"  # Operation failed
        or not event.deep_get("protoPayload", "metadata", "destination")
    ):
        return False

    # Extract source and destination buckets
    source_bucket = event.deep_get("resource", "labels", "bucket_name")
    destination = event.deep_get("protoPayload", "metadata", "destination", default="")

    dest_bucket, _ = _parse_destination(destination)

    # Alert if copying to a different bucket
    if source_bucket and dest_bucket and source_bucket != dest_bucket:
        return True

    return False


def severity(event):
    """Dynamic severity based on whether destination is in a different project."""
    source_project = event.deep_get("resource", "labels", "project_id")
    destination = event.deep_get("protoPayload", "metadata", "destination", default="")
    _, dest_project = _parse_destination(destination)

    if dest_project and source_project and dest_project != source_project:
        return "DEFAULT"

    return "LOW"


def title(event):
    source_bucket = event.deep_get("resource", "labels", "bucket_name", default="Unknown")
    source_project = event.deep_get("resource", "labels", "project_id", default="Unknown")
    destination = event.deep_get("protoPayload", "metadata", "destination", default="")

    dest_bucket, dest_project = _parse_destination(destination)
    if not dest_bucket:
        dest_bucket = "Unknown"

    actor = event.deep_get(
        "protoPayload", "authenticationInfo", "principalEmail", default="Unknown"
    )

    # Different title based on cross-project vs same-project
    if dest_project and source_project != "Unknown" and dest_project != source_project:
        return (
            f"CROSS-PROJECT: GCS object copied from "
            f"[{source_project}/{source_bucket}] to "
            f"[{dest_project}/{dest_bucket}] by [{actor}]"
        )

    return (
        f"GCS object copied from bucket " f"[{source_bucket}] to [{dest_bucket}] " f"by [{actor}]"
    )


def alert_context(event):
    destination = event.deep_get("protoPayload", "metadata", "destination", default="")
    dest_bucket, dest_project = _parse_destination(destination)

    source_project = event.deep_get("resource", "labels", "project_id")
    is_cross_project = dest_project and source_project and dest_project != source_project

    return {
        "principal": event.deep_get("protoPayload", "authenticationInfo", "principalEmail"),
        "source_project": source_project,
        "source_bucket": event.deep_get("resource", "labels", "bucket_name"),
        "destination_project": dest_project,
        "destination_bucket": dest_bucket,
        "is_cross_project": is_cross_project,
        "destination_path": destination,
        "source_object": event.deep_get("protoPayload", "resourceName"),
        "source_ip": event.deep_get("protoPayload", "requestMetadata", "callerIp"),
        "user_agent": event.deep_get("protoPayload", "requestMetadata", "callerSuppliedUserAgent"),
        "bytes_requested": event.deep_get("protoPayload", "metadata", "requested_bytes"),
    }
