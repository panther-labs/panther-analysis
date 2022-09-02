def rule(event):
    if event.get("Source") != "l7ddos" or event.get("Action") == "block":
        return False
    return True


def title(_):
    return "Cloudflare Detected L7 DDoS"
