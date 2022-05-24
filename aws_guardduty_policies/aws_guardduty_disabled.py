REGIONS_REQUIRED = {
    "us-west-2",
}


def policy(resource):
    # Detector IDs are in the following format:
    # [AccountID]:[Region]:AWS.GuardDuty.Detector
    # so we grab the middle part to determine what regions have GuardDuty enabled
    regions_enabled = [detector.split(":")[1] for detector in resource["Detectors"]]
    for region in REGIONS_REQUIRED:
        if region not in regions_enabled:
            return False

    return True
