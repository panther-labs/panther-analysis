# pylint: disable=too-many-public-methods
import datetime

from dateutil import parser
from panther_base_helpers import deep_get
from panther_lookuptable_helpers import LookupTableMatches


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


class GreyNoiseBasic(LookupTableMatches):
    def __init__(self, event):
        super()._register(event, "greynoise_noise_basic")
        self.sublevel = "basic"

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

    def subscription_level(self):
        return self.sublevel

    def ip_address(self, match_field: str) -> list or str:
        return self._lookup(match_field, "ip")

    def classification(self, match_field: str) -> list or str:
        return self._lookup(match_field, "classification")

    def actor(self, match_field: str) -> list or str:
        return self._lookup(match_field, "actor")

    def url(self, match_field: str) -> list or str:
        ip = self._lookup(match_field, "ip")
        if not ip:
            return None
        if isinstance(ip, list):
            return [f"https://www.greynoise.io/viz/ip/{list_ip}" for list_ip in ip]
        return f"https://www.greynoise.io/viz/ip/{ip}"

    def context(self, match_field: str) -> dict:
        return {
            "IP": self.ip_address(match_field),
            "Classification": self.classification(match_field),
            "Actor": self.actor(match_field),
            "GreyNoise_URL": self.url(match_field),
        }


class GreyNoiseAdvanced(GreyNoiseBasic):
    def __init__(self, event):
        super()._register(event, "greynoise_noise_advanced")
        self.sublevel = "advanced"

    def is_bot(self, match_field: str) -> bool:
        return True if self._lookup(match_field, "bot") else False

    def cve_string(self, match_field: str, limit: int = 10) -> str:
        cve_raw = self._lookup(match_field, "cve")
        if isinstance(cve_raw, list):
            return " ".join(cve_raw[:limit])
        return cve_raw

    def cve_list(self, match_field: str) -> list:
        cve_raw = self._lookup(match_field, "cve")
        if isinstance(cve_raw, str):
            return [cve_raw]
        return cve_raw

    def first_seen(self, match_field: str) -> datetime.date:
        t = self._lookup(match_field, "first_seen")
        if not t:
            return None
        if isinstance(t, list):
            length = len(t)
            if length == 0:
                return None
            if length == 1:
                return parser.parse(t)
            min_t = parser.parse(t[0])
            for list_t in t[1:]:
                list_t_parsed = parser.parse(list_t)
                if list_t_parsed < min_t:
                    min_t = list_t_parsed
            return min_t
        return parser.parse(t)

    def last_seen(self, match_field: str) -> datetime.date:
        t = self._lookup(match_field, "last_seen_timestamp")
        if not t:
            return None
        if isinstance(t, list):
            length = len(t)
            if length == 0:
                return None
            if length == 1:
                return parser.parse(t)
            max_t = parser.parse(t[0])
            for list_t in t[1:]:
                list_t_parsed = parser.parse(list_t)
                if list_t_parsed > max_t:
                    max_t = list_t_parsed
            return max_t
        return parser.parse(t)

    def asn(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "asn")

    def category(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "category")

    def city(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "city")

    def country(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "country")

    def country_code(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "country_code")

    def organization(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "organization")

    def operating_system(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "os")

    def region(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "region")

    def is_tor(self, match_field: str) -> bool:
        return True if self._lookup(match_field, "metadata", "tor") else False

    def rev_dns(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata", "rdns")

    def is_spoofable(self, match_field: str) -> bool:
        return True if self._lookup(match_field, "spoofable") else False

    def tags_list(self, match_field: str) -> list:
        tags = self._lookup(match_field, "tags")
        if isinstance(tags, str):
            return [tags]
        return tags

    def tags_string(self, match_field: str, limit: int = 10) -> str:
        tags_raw = self._lookup(match_field, "tags")
        if isinstance(tags_raw, list):
            return " ".join(tags_raw[:limit])
        return tags_raw

    def is_vpn(self, match_field: str) -> bool:
        return True if self._lookup(match_field, "vpn") else False

    def vpn_service(self, match_field: str) -> list or str:
        return self._lookup(match_field, "vpn_service")

    def metadata(self, match_field: str) -> list or str:
        return self._lookup(match_field, "metadata")

    def context(self, match_field: str) -> dict:
        return {
            "IP": self.ip_address(match_field),
            "Classification": self.classification(match_field),
            "Actor": self.actor(match_field),
            "GreyNoise_URL": self.url(match_field),
            "VPN": self.vpn_service(match_field),
            "Metadata": self.metadata(match_field),
            "Tags": self.tags_list(match_field),
            "CVE": self.cve_list(match_field),
        }


class GreyNoiseRIOTBasic(LookupTableMatches):
    def __init__(self, event):
        super()._register(event, "greynoise_riot_basic")
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

    def is_riot(self, match_field: str) -> bool:
        is_riot = self._lookup(match_field, "ip_cidr")
        if not is_riot:
            return False
        if isinstance(is_riot, list):  # at least 1
            for list_is_riot in is_riot:
                if list_is_riot:
                    return True
            return False
        return True

    def ip_address(self, match_field: str) -> list or str:
        return self._lookup(match_field, "ip_cidr")

    def name(self, match_field: str) -> list or str:
        return self._lookup(match_field, "provider", "name")

    def url(self, match_field: str) -> list or str:
        ip_stripped = self._lookup(match_field, "ip_cidr")
        if not ip_stripped:
            return None
        if isinstance(ip_stripped, list):
            return [
                f"https://www.greynoise.io/viz/ip/{list_ip_stripped}"
                for list_ip_stripped in ip_stripped
            ]
        return f"https://www.greynoise.io/viz/ip/{ip_stripped.split('/')[0]}"

    def last_updated(self, match_field: str) -> datetime.date:
        t = self._lookup(match_field, "scan_time")
        if not t:
            return None
        if isinstance(t, list):
            length = len(t)
            if length == 0:
                return None
            if length == 1:
                return parser.parse(t)
            max_t = parser.parse(t[0])
            for list_t in t[1:]:
                list_t_parsed = parser.parse(list_t)
                if list_t_parsed > max_t:
                    max_t = list_t_parsed
            return max_t
        return parser.parse(t)

    def context(self, match_field: str) -> dict:
        return {
            "Is_RIOT": self.is_riot(match_field),
            "IP": self.ip_address(match_field),
            "Name": self.name(match_field),
            "GreyNoise_URL": self.url(match_field),
        }


class GreyNoiseRIOTAdvanced(GreyNoiseRIOTBasic):
    def __init__(self, event):
        super()._register(event, "greynoise_riot_advanced")
        self.sublevel = "advanced"

    def description(self, match_field: str) -> list or str:
        return self._lookup(match_field, "provider", "description")

    def category(self, match_field: str) -> list or str:
        return self._lookup(match_field, "provider", "category")

    def explanation(self, match_field: str) -> list or str:
        return self._lookup(match_field, "provider", "explanation")

    def reference(self, match_field: str) -> list or str:
        return self._lookup(match_field, "provider", "reference")

    def trust_level(self, match_field: str) -> int or list or str:
        return self._lookup(match_field, "provider", "trust_level")

    def context(self, match_field: str) -> dict:
        return {
            "Is_RIOT": self.is_riot(match_field),
            "IP": self.ip_address(match_field),
            "Name": self.name(match_field),
            "GreyNoise_URL": self.url(match_field),
            "Provider Data": self._lookup(match_field, "provider"),
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


def GreyNoiseSeverity(event, field, default="MEDIUM"):
    # Set Severity based on GreyNoise classification.
    # If unknown to GreyNoise return default
    noise = GetGreyNoiseObject(event)
    riot = GetGreyNoiseRiotObject(event)

    # If IP exists in RIOT Dataset it is known good, lower alert severity
    if riot.is_riot(field):
        return "INFO"

    classification = noise.classification(field)
    if isinstance(classification, list):
        highest_severity = "INFO"
        for list_classification in classification:
            severity = GreyNoiseSeverityDecode(list_classification, default)
            if SeverityGreaterThan(severity, highest_severity):
                highest_severity = severity
        return highest_severity

    # If classification is unknown default to medium
    return GreyNoiseSeverityDecode(classification, default)


def GreyNoiseSeverityDecode(classification: str, default: str) -> str:
    if classification == "malicious":
        return "CRITICAL"
    if classification == "benign":
        return "LOW"
    return default


_SEVERITIES = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def SeverityGreaterThan(sev1: str, sev2: str) -> bool:
    return _SEVERITIES.get(sev1) > _SEVERITIES.get(sev2)
