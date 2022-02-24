import ast
import datetime

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
        if self.noise is None:
            self.advanced_enabled = deep_get(event, "p_enrichment", "greynoise_noise_advanced")
            if self.advanced_enabled is not None:
                raise PantherGreyNoiseException("advanced")

    def ip_address(self, match_field) -> str:
        return deep_get(self.noise, match_field, "ip")

    def classification(self, match_field) -> str:
        return deep_get(self.noise, match_field, "classification")

    def actor(self, match_field) -> str:
        return deep_get(self.noise, match_field, "actor")

    def url(self, match_field) -> str:
        return f"https://www.greynoise.io/viz/ip/{deep_get(self.noise, match_field, 'ip')}"


class GreyNoiseAdvanced:
    def __init__(self, event):
        self.noise = deep_get(event, "p_enrichment", "greynoise_noise_advanced")
        if self.noise is None:
            self.basic_enabled = deep_get(event, "p_enrichment", "greynoise_noise_basic")
            if self.basic_enabled is not None:
                raise PantherGreyNoiseException("basic")

    def ip_address(self, match_field) -> str:
        return deep_get(self.noise, match_field, "ip")

    def classification(self, match_field) -> str:
        return deep_get(self.noise, match_field, "classification")

    def actor(self, match_field) -> str:
        return deep_get(self.noise, match_field, "actor")

    def url(self, match_field) -> str:
        return f"https://www.greynoise.io/viz/ip/{deep_get(self.noise, match_field, 'ip')}"

    def is_bot(self, match_field) -> bool:
        return ast.literal_eval(deep_get(self.noise, match_field, "bot"))

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

    def metadata(self, match_field) -> dict:
        return deep_get(self.noise, match_field, "metadata")

    def is_spoofable(self, match_field) -> str:
        return ast.literal_eval(deep_get(self.noise, match_field, "spoofable"))

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
        return ast.literal_eval(deep_get(self.noise, match_field, "vpn"))

    def vpn_service(self, match_field) -> str:
        return deep_get(self.noise, match_field, "vpn_service")


class GreyNoiseRIOTBasic:
    def __init__(self, event):
        self.riot = deep_get(event, "p_enrichment", "greynoise_riot_basic")
        if self.riot is None:
            self.advanced_enabled = deep_get(event, "p_enrichment", "greynoise_riot_advanced")
            if self.advanced_enabled is not None:
                raise PantherGreyNoiseException("advanced")

    def ip_address(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "ip")

    def name(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "name")

    def url(self, match_field) -> str:
        return f"https://www.greynoise.io/viz/ip/{deep_get(self.riot, match_field, 'ip')}"

    def last_seen(self, match_field) -> datetime.date:
        return parser.parse(deep_get(self.riot, match_field, "provider", "last_seen"))


class GreyNoiseRIOTAdvanced:
    def __init__(self, event):
        self.riot = deep_get(event, "p_enrichment", "greynoise_riot_advanced")
        if self.riot is None:
            self.basic_enabled = deep_get(event, "p_enrichment", "greynoise_riot_basic")
            if self.basic_enabled is not None:
                raise PantherGreyNoiseException("basic")

    def ip_address(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "ip")

    def name(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "name")

    def url(self, match_field) -> str:
        return f"https://www.greynoise.io/viz/ip/{deep_get(self.riot, match_field, 'ip')}"

    def last_updated(self, match_field) -> datetime.date:
        return parser.parse(deep_get(self.riot, match_field, "provider", "last_updated"))

    def description(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "description")

    def explanation(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "explanation")

    def reference(self, match_field) -> str:
        return deep_get(self.riot, match_field, "provider", "reference")
