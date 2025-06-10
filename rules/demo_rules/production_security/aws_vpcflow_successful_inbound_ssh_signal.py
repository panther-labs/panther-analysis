def rule(event):
    # Only match accepted (successful) inbound TCP connections to port 22
    return (
        event.get("action") == "ACCEPT"
        and event.get("protocol") == 6  # TCP protocol
        and event.get("dstPort") == 22
        and (
            # Inbound: source is not private (external), destination is private (internal)
            # VPCFlow logs do not have explicit direction, so infer by IPs
            not event.get("srcAddr", "").startswith("172.")
            and event.get("dstAddr", "").startswith("172.")
        )
    )
