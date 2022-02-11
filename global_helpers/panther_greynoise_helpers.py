import ast
import datetime

from dateutil import parser
from panther_base_helpers import deep_get


class GreyNoiseBasic:
    def __init__(self, event):
        self.noise = deep_get(event, "p_enrichment", "greynoise_noise_basic")

    def ip_address(self, match_field) -> str:
        return deep_get(self.noise, match_field, "ip")

    def classification(self, match_field) -> str:
        return deep_get(self.noise, match_field, "classification")

    def actor(self, match_field) -> str:
        return deep_get(self.noise, match_field, "actor")

    def url(self, match_field) -> str:
        return f"www.greynoise.io/viz/ip/{deep_get(self.noise, match_field, 'ip')}"


class GreyNoiseAdvanced:
    def __init__(self, event):
        self.noise = deep_get(event, "p_enrichment", "greynoise_noise_advanced")

    def ip_address(self, match_field) -> str:
        return deep_get(self.noise, match_field, "classification")

    def classification(self, match_field) -> str:
        return deep_get(self.noise, match_field, "classification")

    def actor(self, match_field) -> str:
        return deep_get(self.noise, match_field, "actor")

    def url(self, match_field) -> str:
        return f"www.greynoise.io/viz/ip/{deep_get(self.noise, match_field, 'ip')}"

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


class GreyNoiseRIOT:
    def __init__(self, event):
        self.riot = deep_get(event, "p_enrichment", "greynoise_riot_basic")

    def ip_range(self, match_field) -> str:
        return deep_get(self.riot, match_field, "ip_cidr")

    def ip_info(self, match_field) -> object:
        return deep_get(self.riot, match_field, "provider")

    def scan_time(self, match_field) -> datetime.date:
        return parser.parse(deep_get(self.riot, match_field, "scan_time"))
