def rule(_):
    return True

def title(event):
    return (
        f"A data export has been initiated from source cloud [{event.get('source_cloud','<SOURCE_CLOUD_NOT_FOUND>')}] "
        f"in source region [{event.get('source_region','<SOURCE_REGION_NOT_FOUND>')}] "
        f"to target cloud [{event.get('target_cloud','<TARGET_CLOUD_NOT_FOUND>')}] "
        f"in target region [{event.get('target_region','<TARGET_REGION_NOT_FOUND>')}] "
        f"with transfer type [{event.get('transfer_type','<TARGET_REGION_NOT_FOUND>')}] "
        f"for [{event.get('bytes_transferred','<BYTES_NOT_FOUND>')}] bytes."
    )
 