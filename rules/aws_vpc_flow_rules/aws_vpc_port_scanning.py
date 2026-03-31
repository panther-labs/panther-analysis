from ipaddress import ip_address

COMMON_PORTS = {80, 123, 443, 445, 53, 853, 2049}


def rule(event):
    if event.get("flowDirection") != "egress":
        return False
    src_addr = event.get("srcAddr", "")
    if not src_addr or src_addr == "null":
        return False
    if event.get("srcPort") in COMMON_PORTS:
        return False
    if event.get("dstPort") in COMMON_PORTS:
        return False
    return True


def title(event):
    src = event.get("srcAddr", "Unknown")
    dst = event.get("dstAddr", "Unknown")
    return f"Port Scanning Detected from [{src}] to [{dst}]"


def dedup(event):
    src = event.get("srcAddr", "")
    dst = event.get("dstAddr", "")
    vpc = event.get("vpcId", "")
    region = event.get("region", "")
    subnet = event.get("subNetId", "")
    return f"{src}:{dst}:{vpc}:{region}:{subnet}"


def unique(event):
    return str(event.get("dstPort", ""))


def severity(event):
    try:
        src = ip_address(event.get("srcAddr", ""))
        if src.is_private:
            return "HIGH"
    except ValueError:
        pass
    return "DEFAULT"
