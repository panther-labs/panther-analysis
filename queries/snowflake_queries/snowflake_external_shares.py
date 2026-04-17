def rule(_):
    return True


def title(event):
    return (
        "A data export has been initiated from source cloud "
        f"[{event.get('source_cloud','<SOURCE_CLOUD_NOT_FOUND>')}] "
        f"in source region [{event.get('source_region','<SOURCE_REGION_NOT_FOUND>')}] "
        f"to target cloud [{event.get('target_cloud','<TARGET_CLOUD_NOT_FOUND>')}] "
        f"in target region [{event.get('target_region','<TARGET_REGION_NOT_FOUND>')}] "
        f"with transfer type [{event.get('transfer_type','<TRANSFER_TYPE_NOT_FOUND>')}] "
        f"for [{event.get('bytes_transferred','<BYTES_NOT_FOUND>')}] bytes."
    )
