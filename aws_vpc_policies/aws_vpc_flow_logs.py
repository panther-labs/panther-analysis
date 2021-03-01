def policy(resource):
    if resource["FlowLogs"] is None:
        return False

    for flow in resource["FlowLogs"]:
        if flow["FlowLogStatus"] == "ACTIVE" and (
            flow["TrafficType"] == "REJECT" or flow["TrafficType"] == "ALL"
        ):
            return True

    return False
