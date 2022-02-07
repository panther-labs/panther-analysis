import ast
import datetime
from typing import Union

from dateutil import parser
from panther_base_helpers import deep_get


class GreyNoise:
    def __init__(self, event):
        self.noise = deep_get(event, "p_enrichment", "greynoise")

    # Fields available for all users
    @property
    def ip_address(self) -> str:
        return self.noise.get("ip")

    @property
    def classification(self) -> str:
        return self.noise.get("classification")

    @property
    def actor(self) -> str:
        return self.noise.get("actor")

    @property
    def url(self) -> str:
        return f"www.greynoise.io/viz/ip/{self.noise.get('ip')}"

    # Advanced features
    # GreyNoise Advanced Subscription
    def _check_advanced(self, field) -> bool:
        if self.noise.get(field) is None:
            return False
        return True

    @property
    def is_bot(self) -> Union[bool, str]:
        if self._check_advanced("bot") is False:
            return "GreyNoise Advanced Subscription required for this field"
        return ast.literal_eval(self.noise.get("bot"))

    @property
    def cve_string(self) -> str:
        if self._check_advanced("cve") is False:
            return "GreyNoise Advanced Subscription required for this field"
        cve_raw = self.noise.get("cve")
        if isinstance(cve_raw, list):
            return " ".join(cve_raw)
        return cve_raw

    @property
    def cve_list(self) -> Union[list, str]:
        if self._check_advanced("cve") is False:
            return "GreyNoise Advanced Subscription required for this field"
        cve_raw = self.noise.get("cve")
        if isinstance(cve_raw, str):
            return [cve_raw]
        return cve_raw

    @property
    def first_seen(self) -> Union[datetime, str]:
        if self._check_advanced("first_seen") is False:
            return "GreyNoise Advanced Subscription required for this field"
        return parser.parse(self.noise.get("first_seen"))

    @property
    def last_seen(self):
        if self._check_advanced("last_seen_timestamp") is False:
            return "GreyNoise Advanced Subscription required for this field"
        return parser.parse(self.noise.get("last_seen_timestamp"))

    @property
    def metadata(self) -> Union[dict, str]:
        if self._check_advanced("metadata") is False:
            return "GreyNoise Advanced Subscription required for this field"
        return self.noise.get("metadata")

    @property
    def is_spoofable(self) -> Union[bool, str]:
        if self._check_advanced("spoofable") is False:
            return "GreyNoise Advanced Subscription required for this field"
        return ast.literal_eval(self.noise.get("spoofable"))

    @property
    def tags(self) -> Union[list, str]:
        if self._check_advanced("tags") is False:
            return "GreyNoise Advanced Subscription required for this field"
        tags = self.noise.get("tags")
        if isinstance(tags, str):
            return [tags]
        return tags

    @property
    def is_vpn(self) -> Union[bool, str]:
        if self._check_advanced("vpn") is False:
            return "GreyNoise Advanced Subscription required for this field"
        return ast.literal_eval(self.noise.get("vpn"))

    @property
    def vpn_service(self) -> str:
        if self._check_advanced("vpn_service") is False:
            return "GreyNoise Advanced Subscription required for this field"
        return self.noise.get("vpn_service")
