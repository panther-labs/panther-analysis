import re


def rule(event):
    if any(
        [
            re.match(
                r"^v.*.Compute.PacketMirrorings.Get$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.PacketMirrorings.Delete$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.PacketMirrorings.Insert$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.PacketMirrorings.Patch$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.PacketMirrorings.List$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
            re.match(
                r"^v.*.Compute.PacketMirrorings.aggregatedList$",
                event.deep_get("protoPayload", "methodName", default=""),
            ),
        ]
    ):
        return True
    return False
