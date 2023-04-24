from panther_greynoise_helpers import GetGreyNoiseObject, GetGreyNoiseRiotObject
from panther_base_helpers import deep_get, crowdstrike_detection_alert_context

def rule(event):
    # Return True to match the log event and trigger an alert.

    global NOISE  
    NOISE = GetGreyNoiseObject(event)
    
    return (NOISE.classification('RemoteAddressIP4') == 'malicious') 

def title(event):

    ip = event.get("RemoteAddressIP4")
    defanged = ip.split('.')
    defanged = '[.]'.join(defanged)

    if NOISE.country('RemoteAddressIP4') and NOISE.last_seen("RemoteAddressIP4"):
        country = NOISE.country('RemoteAddressIP4')
        last_seen = NOISE.last_seen("RemoteAddressIP4")
    else:
        country = "NotFound"
        last_seen = "NotFound"

    return f'[Greynoise] IP {defanged} classified as {NOISE.classification("RemoteAddressIP4")} from {country}. GN last seen: {last_seen}'


def severity(event):
    if NOISE.actor('RemoteAddressIP4') == "unknown":
        return "CRITICAL"
    else:
        return "HIGH"

def alert_context(event):
    #  (Optional) Return a dictionary with additional data to be included in the alert sent to the SNS/SQS/Webhook destination
    return {
        "GreyNoise": { 
            "actor": NOISE.actor('RemoteAddressIP4'),
            "bot": NOISE.is_bot('RemoteAddressIP4'),
            "country": NOISE.country('RemoteAddressIP4')
            },
        "IPInfo": {
            "lat": deep_get(event, "p_enrichment", "ipinfo_location", "RemoteAddressIP4", "lat"),
            "lng": deep_get(event, "p_enrichment", "ipinfo_location", "RemoteAddressIP4", "lng") 

        }
    
    } + crowdstrike_detection_alert_context