def rule(event):
    if event.get("Source") != "l7ddos":
        return False
    return True


def title(_):
    return f"Cloudflare Detected L7 DDoS"
