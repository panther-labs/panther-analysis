from panther_aws_helpers import aws_guardduty_context

def rule(event):
    # Only match on high severity or above
    if event.deep_get("service", "additionalInfo", "sample"):
        return False
    severity = float(event.get("severity", 0))
    if severity < 7.0:
        return False
    finding_type = event.get("type", "")
    return finding_type in [
        "CryptoCurrency:EC2/BitcoinTool.B",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    ]

def title(event):
    instance_id = event.deep_get("resource", "instanceDetails", "instanceId", "unknown")
    return f"GuardDuty: Bitcoin mining activity detected on EC2 instance {instance_id}"

def runbook(event):
    instance_id = event.deep_get("resource", "instanceDetails", "instanceId", "unknown")
    return (
        f"1. Investigate the instance's recent activity for signs of unauthorized cryptocurrency mining.\n"
        f"2. Check for unusual outbound network traffic or high CPU usage on {instance_id}.\n"
        f"3. Consider isolating or stopping the instance if compromise is confirmed.\n"
        f"4. Review IAM activity and permissions associated with the instance.\n"
        f"5. Document findings and escalate according to your incident response plan."
    )

def alert_context(event):
    context = aws_guardduty_context(event)
    context["finding_type"] = event.get("type", "")
    context["instance_id"] = event.deep_get("resource", "instanceDetails", "instanceId", "unknown")
    context["severity"] = event.get("severity", "")
    return context 