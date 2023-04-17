def rule(_):
    return True

def title(event):
    return (
        f"A data export has been initiated from source cloud [{event.get('source_cloud','<SOURCE_NOT_FOUND>')}] "
        f"to target cloud [{event.get('target_cloud','<TARGET_CLOUD_NOT_FOUND>')}]."
    )
 