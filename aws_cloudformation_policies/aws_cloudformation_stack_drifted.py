def policy(resource):
    return resource['DriftInformation']['StackDriftStatus'] != "DRIFTED"
