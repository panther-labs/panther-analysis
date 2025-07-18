def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "elasticfilesystem.amazonaws.com",
            event.deep_get("eventName", default="") == "DeleteFileSystem",
        ]
    ):
        return True
    return False
