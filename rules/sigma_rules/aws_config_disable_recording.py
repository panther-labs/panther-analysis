def rule(event):
    if all(
        [
            event.deep_get("eventSource", default="") == "config.amazonaws.com",
            event.deep_get("eventName", default="")
            in ["DeleteDeliveryChannel", "StopConfigurationRecorder"],
        ]
    ):
        return True
    return False
