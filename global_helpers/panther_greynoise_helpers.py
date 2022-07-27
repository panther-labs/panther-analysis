# pylint: disable=too-many-public-methods
import datetime
from distutils.log import error
from webbrowser import get

from dateutil import parser
from panther_base_helpers import deep_get


class PantherGreyNoiseException(Exception):
    def __init__(self, sublevel):
        if sublevel == "advanced":
            message = (
                "This account is configured with an advanced GreyNoise Subscription. Please "
                "use GreyNoiseAdvanced and GreyNoiseRIOTAdvanced "
            )
        elif sublevel == "basic":
            message = (
                "This account is configured with a basic GreyNoise Subscription. Please use "
                "GreyNoiseBasic and GreyNoiseRIOTBasic "
            )
        else:
            message = "Unknown Error Reading GreyNoise Data"
        super().__init__(message)


class GreyNoiseBasic:
    def __init__(self, event):
        self.noise = deep_get(event, "p_enrichment", "greynoise_noise_basic")
        self.sublevel = "basic"

    def subscription_level(self):
        return self.sublevel

    def __getattr__(self, name):
        def advanced_only():
            advanced_methods = [
                method
                for method in dir(GreyNoiseAdvanced)
                if method.startswith("__") is False and method not in dir(self)
            ]
            if name in advanced_methods:
                raise PantherGreyNoiseException(self.sublevel)

        return advanced_only()

    def ip_address(self, match_field) -> str:
        deep_get_call = deep_get(self.noise, match_field, "ip")
        if type(deep_get_call) is list:
            raise error("~This is not the method you are looking for~ Try ip_addresses()")
        else:
            return deep_get_call

    def ip_addresses(self) -> list:
        deep_get_call = deep_get(self.noise)
        if type(deep_get_call) is list:
            return deep_get_call
        else:
            raise error("~This is not the method you are looking for~ Try ip_address()")

    def classification(self, match_field) -> str:
        return deep_get(self.noise, match_field, "classification")

    def actor(self, match_field) -> str:
        return deep_get(self.noise, match_field, "actor")

    def url(self, match_field) -> str:
        return f"https://www.greynoise.io/viz/ip/{deep_get(self.noise, match_field, 'ip')}"

    def context(self, match_field) -> dict:
        return {
            "IP": self.ip_address(match_field),
            "Classification": self.classification(match_field),
            "Actor": self.actor(match_field),
            "GreyNoise_URL": self.url(match_field),
        }


class GreyNoiseAdvanced:
    def __init__(self, event):
        self.noise = deep_get(event, "p_enrichment", "greynoise_noise_advanced")
        self.sublevel = "advanced"

    def subscription_level(self):
        return self.sublevel

    def ip_address(self, match_field) -> str:
        deep_get_call = deep_get(self.noise, match_field, "ip")
        if type(deep_get_call) is list:
            raise error("~This is not the method you are looking for~ Try ip_addresses()")
        else:
            return deep_get_call

    def ip_addresses(self) -> list:
        deep_get_call = deep_get(self.noise)
        if type(deep_get_call) is list:
            return deep_get_call
        else:
            raise error("~This is not the method you are looking for~ Try ip_address()")

    def classification(self, match_field) -> str:
        return deep_get(self.noise, match_field, "classification")

    def actor(self, match_field) -> str:
        return deep_get(self.noise, match_field, "actor")

    def url(self, match_field) -> str:
        return f"https://www.greynoise.io/viz/ip/{deep_get(self.noise, match_field, 'ip')}"

    def is_bot(self, match_field) -> bool:
        return deep_get(self.noise, match_field, "bot")

    def cve_string(self, match_field, limit: int = 10) -> str:
        cve_raw = deep_get(self.noise, match_field, "cve")
        if isinstance(cve_raw, list):
            return " ".join(cve_raw[:limit])
        return cve_raw

    def cve_list(self, match_field) -> list:
        cve_raw = deep_get(self.noise.get, match_field, "cve")
        if isinstance(cve_raw, str):
            return [cve_raw]
        return cve_raw

    def first_seen(self, match_field) -> datetime.date:
        return parser.parse(deep_get(self.noise, match_field, "first_seen"))

    def last_seen(self, match_field) -> datetime.date:
        return parser.parse(deep_get(self.noise, match_field, "last_seen_timestamp"))

    def asn(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "asn")

    def category(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "category")

    def city(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "city")

    def country(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "country")

    def country_code(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "country_code")

    def organization(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "organization")

    def operating_system(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "os")

    def region(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "region")

    def is_tor(self, match_field) -> bool:
        return deep_get(self.noise, match_field, "metadata", "tor")

    def rev_dns(self, match_field) -> str:
        return deep_get(self.noise, match_field, "metadata", "rdns")

    def is_spoofable(self, match_field) -> str:
        return deep_get(self.noise, match_field, "spoofable")

    def tags_list(self, match_field) -> list:
        tags = deep_get(self.noise, match_field, "tags")
        if isinstance(tags, str):
            return [tags]
        return tags

    def tags_string(self, match_field, limit: int = 10) -> str:
        tags_raw = deep_get(self.noise, match_field, "tags")
        if isinstance(tags_raw, list):
            return " ".join(tags_raw[:limit])
        return tags_raw

    def is_vpn(self, match_field) -> bool:
        return deep_get(self.noise, match_field, "vpn")

    def vpn_service(self, match_field) -> str:
        return deep_get(self.noise, match_field, "vpn_service")

    def context(self, match_field) -> dict:
        return {
            "IP": self.ip_address(match_field),
            "Classification": self.classification(match_field),
            "Actor": self.actor(match_field),
            "GreyNoise_URL": self.url(match_field),
            "VPN": self.vpn_service(match_field),
            "Metadata": deep_get(self.noise, match_field, "metadata"),
            "Tags": self.tags_list(match_field),
            "CVE": self.cve_list(match_field),
        }


class GreyNoiseRIOTBasic:
    def __init__(self, event):
        self.riot = deep_get(event, "p_enrichment", "greynoise_riot_basic")
        self.sublevel = "basic"

    def __getattr__(self, name):
        def advanced_only():
            advanced_methods = [
                method
                for method in dir(GreyNoiseRIOTAdvanced)
                if method.startswith("__") is False and method not in dir(self)
            ]
            if name in advanced_methods:
                raise PantherGreyNoiseException(self.sublevel)

        return advanced_only()

    def subscription_level(self):
        return self.sublevel

    def is_riot(self, match_field) -> bool:
        return deep_get(self.riot, match_field, "ip_cidr") is not None

    def ip_address(self, match_field) -> str:
        return deep_get(self.riot, match_field, "ip_cidr")

    def name(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "name")

    def url(self, match_field) -> str:
        ip_stripped = deep_get(self.riot, match_field, "ip_cidr", default="")
        return f"https://www.greynoise.io/viz/ip/{ip_stripped.split('/')[0]}"

    def last_updated(self, match_field) -> datetime.date:
        return parser.parse(deep_get(self.riot, match_field, "scan_time"))

    def context(self, match_field) -> dict:
        return {
            "Is_RIOT": self.is_riot(match_field),
            "IP": self.ip_address(match_field),
            "Name": self.name(match_field),
            "GreyNoise_URL": self.url(match_field),
        }


class GreyNoiseRIOTAdvanced:
    def __init__(self, event):
        self.riot = deep_get(event, "p_enrichment", "greynoise_riot_advanced")
        self.sublevel = "advanced"

    def subscription_level(self):
        return self.sublevel

    def is_riot(self, match_field) -> bool:
        return deep_get(self.riot, match_field, "ip_cidr") is not None

    def ip_address(self, match_field) -> str:
        return deep_get(self.riot, match_field, "ip_cidr")

    def name(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "name")

    def url(self, match_field) -> str:
        ip_stripped = deep_get(self.riot, match_field, "ip_cidr", default="")
        return f"https://www.greynoise.io/viz/ip/{ip_stripped.split('/')[0]}"

    def last_updated(self, match_field) -> datetime.date:
        return parser.parse(deep_get(self.riot, match_field, "scan_time"))

    def description(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "description")

    def explanation(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "explanation")

    def reference(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "reference")

    def trust_level(self, match_field) -> int:
        return deep_get(self.riot, match_field, "provider", "trust_level")

    def context(self, match_field) -> dict:
        return {
            "Is_RIOT": self.is_riot(match_field),
            "IP": self.ip_address(match_field),
            "Name": self.name(match_field),
            "GreyNoise_URL": self.url(match_field),
            "Provider Data": deep_get(self.riot, match_field, "provider"),
        }


# pylint: disable=invalid-name
def GetGreyNoiseObject(event):
    if deep_get(event, "p_enrichment", "greynoise_noise_advanced"):
        return GreyNoiseAdvanced(event)
    return GreyNoiseBasic(event)


def GetGreyNoiseRiotObject(event):
    if deep_get(event, "p_enrichment", "greynoise_riot_advanced"):
        return GreyNoiseRIOTAdvanced(event)
    return GreyNoiseRIOTBasic(event)


def GreyNoiseSeverity(event, ip, default="MEDIUM"):
    # Set Severity based on GreyNoise classification. If unknown to GreyNoise
    # return default
    noise = GetGreyNoiseObject(event)
    riot = GetGreyNoiseRiotObject(event)

    # If IP exists in RIOT Dataset it is known good, lower alert severity
    if riot.is_riot(ip):
        return "INFO"

    if noise.classification(ip) == "malicious":
        return "CRITICAL"
    if noise.classification(ip) == "benign":
        return "LOW"
    # If classification is unknown default to medium
    return default
