from panther_greynoise_helpers import GreyNoiseAdvanced, GreyNoiseBasic


# This rule was created to test GreyNoise helper functionality and should not be enabled
def rule(event):
    advanced_noise = GreyNoiseAdvanced(event)
    basic_noise = GreyNoiseBasic(event)
    return (
        # Testing GreyNoise Advanced Extraction
        advanced_noise.ip_address("srcAddr") == "4.4.4.4"
        and advanced_noise.classification("srcAddr") == "malicious"
        and advanced_noise.actor("srcAddr") == "dr.evil"
        and advanced_noise.url("srcAddr") == "www.greynoise.io/viz/ip/4.4.4.4"
        and "CVE-2018-13379" in advanced_noise.cve_string("srcAddr")
        and advanced_noise.metadata("srcAddr").get("country") == "Denmark"
        and advanced_noise.vpn_service("srcAddr") == "MULLVAD_VPN"
        # Testing GreyNoise Basic Extraction
        and basic_noise.ip_address("srcAddr") == "4.4.4.4"
        and basic_noise.classification("srcAddr") == "malicious"
        and basic_noise.actor("srcAddr") == "unknown"
        and basic_noise.url("srcAddr") == "www.greynoise.io/viz/ip/4.4.4.4"
    )


def alert_context(event):
    # if our test returns False this will print out a dict of all the items tested and their values
    advanced_noise = GreyNoiseAdvanced(event)
    basic_noise = GreyNoiseBasic(event)

    context = {"advanced": {}, "basic": {}}
    # Build Advanced Output Dictionary
    context["advanced"]["ip_address"] = advanced_noise.ip_address("srcAddr")
    context["advanced"]["classification"] = advanced_noise.classification("srcAddr") == "malicious"
    context["advanced"]["actor"] = advanced_noise.actor("srcAddr")
    context["advanced"]["url"] = advanced_noise.url("srcAddr")
    context["advanced"]["country"] = advanced_noise.metadata("srcAddr").get("country")
    context["advanced"]["cve_string"] = advanced_noise.cve_string("srcAddr")
    context["advanced"]["vpn_service"] = advanced_noise.vpn_service("srcAddr")
    # Build Basic Output Dictionary
    context["basic"]["ip_address"] = basic_noise.ip_address("srcAddr")
    context["basic"]["classification"] = basic_noise.classification("srcAddr") == "malicious"
    context["basic"]["actor"] = basic_noise.actor("srcAddr")
    context["basic"]["url"] = basic_noise.url("srcAddr")

    return context
