# pylint: disable=too-many-public-methods
import datetime
from collections.abc import Sequence
from typing import Union

from dateutil import parser
from panther_lookuptable_helpers import LookupTableMatches

_SEVERITIES = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def greynoise_severity_decode(classification: str, default: str) -> str:
    if classification == "malicious":
        return "CRITICAL"
    if classification == "benign":
        return "LOW"
    return default


def severity_greater_than(sev1: str, sev2: str) -> bool:
    return _SEVERITIES.get(sev1) > _SEVERITIES.get(sev2)


# GreyNoise V3 API Helpers


def _find_greynoise_v3_lut_name(event) -> str:
    """Auto-detect the GreyNoise V3 lookup table name from the event enrichment.

    The LUT name is user-customizable in Panther but always ends with '_noise'.
    V3 data is identified by the presence of 'internet_scanner_intelligence' in the values.
    """
    enrichment = event.deep_get("p_enrichment", default={})
    for lut_name in enrichment.keys():
        if not lut_name.endswith("_noise"):
            continue
        for match_data in enrichment.get(lut_name, {}).values():
            if hasattr(match_data, "get") and match_data.get("internet_scanner_intelligence"):
                return lut_name
    return None


class GreyNoiseV3ScannerIntelligence(LookupTableMatches):
    """Helper to get GreyNoise V3 Internet Scanner Intelligence for enriched fields"""

    def __init__(self, event, lut_name=None):
        super().__init__()
        if lut_name is None:
            lut_name = _find_greynoise_v3_lut_name(event)
        if lut_name:
            super()._register(event, lut_name)

    def _scanner_lookup(self, match_field: str, *keys):
        return self._lookup(match_field, "internet_scanner_intelligence", *keys)

    def actor(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "actor")

    def is_bot(self, match_field: str) -> bool:
        return bool(self._scanner_lookup(match_field, "bot"))

    def classification(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "classification")

    def cve_list(self, match_field: str) -> list:
        cves = self._scanner_lookup(match_field, "cves")
        if not cves:
            return []
        if isinstance(cves, str):
            return [cves]
        return cves

    def cve_string(self, match_field: str, limit: int = 10) -> str:
        cves = self.cve_list(match_field)
        if isinstance(cves, Sequence) and not isinstance(cves, str):
            return " ".join(cves[:limit])
        return cves

    def first_seen(self, match_field: str) -> datetime.date:
        time = self._scanner_lookup(match_field, "first_seen")
        if not time:
            return None
        try:
            if isinstance(time, Sequence) and not isinstance(time, str):
                if len(time) == 0:
                    return None
                return min(parser.parse(t) for t in time)
            return parser.parse(time)
        except (ValueError, TypeError):
            return None

    def found(self, match_field: str) -> bool:
        return bool(self._scanner_lookup(match_field, "found"))

    def last_seen(self, match_field: str) -> datetime.date:
        time = self._scanner_lookup(match_field, "last_seen_timestamp")
        if not time:
            return None
        try:
            if isinstance(time, Sequence) and not isinstance(time, str):
                if len(time) == 0:
                    return None
                return max(parser.parse(t) for t in time)
            return parser.parse(time)
        except (ValueError, TypeError):
            return None

    def ip_address(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "ip")

    def url(self, match_field: str) -> Union[list[str], str, None]:
        ip_address = self._lookup(match_field, "ip")
        if not ip_address:
            return None
        if isinstance(ip_address, Sequence) and not isinstance(ip_address, str):
            return [f"https://www.greynoise.io/viz/ip/{addr}" for addr in ip_address]
        return f"https://www.greynoise.io/viz/ip/{ip_address}"

    # Metadata accessors
    def asn(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "asn")

    def carrier(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "carrier")

    def category(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "category")

    def datacenter(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "datacenter")

    def domain(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "domain")

    def latitude(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "latitude")

    def longitude(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "longitude")

    def is_mobile(self, match_field: str) -> bool:
        return bool(self._scanner_lookup(match_field, "metadata", "mobile"))

    def organization(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "organization")

    def operating_system(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "os")

    def rev_dns(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "rdns")

    def rev_dns_parent(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "rdns_parent")

    def region(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "region")

    def sensor_count(self, match_field: str) -> Union[int, list]:
        return self._scanner_lookup(match_field, "metadata", "sensor_count")

    def sensor_hits(self, match_field: str) -> Union[int, list]:
        return self._scanner_lookup(match_field, "metadata", "sensor_hits")

    def source_city(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "source_city")

    def source_country(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "source_country")

    def source_country_code(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata", "source_country_code")

    def destination_countries(self, match_field: str) -> list:
        return self._scanner_lookup(match_field, "metadata", "destination_countries")

    def metadata(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "metadata")

    # Top-level scanner fields
    def is_spoofable(self, match_field: str) -> bool:
        return bool(self._scanner_lookup(match_field, "spoofable"))

    def tags(self, match_field: str) -> list:
        tags = self._scanner_lookup(match_field, "tags")
        if not tags:
            return []
        return tags

    def tag_names(self, match_field: str) -> list:
        tags = self.tags(match_field)
        if not tags:
            return []
        if isinstance(tags, Sequence) and not isinstance(tags, str):
            return [str(t.get("name", "")) if hasattr(t, "get") else str(t) for t in tags]
        return []

    def tag_names_string(self, match_field: str, limit: int = 10) -> str:
        names = self.tag_names(match_field)
        if isinstance(names, Sequence) and not isinstance(names, str):
            return " ".join(names[:limit])
        return names

    def is_tor(self, match_field: str) -> bool:
        return bool(self._scanner_lookup(match_field, "tor"))

    def is_vpn(self, match_field: str) -> bool:
        return bool(self._scanner_lookup(match_field, "vpn"))

    def vpn_service(self, match_field: str) -> Union[list[str], str]:
        return self._scanner_lookup(match_field, "vpn_service")

    def context(self, match_field: str) -> dict:
        return {
            "IP": self.ip_address(match_field),
            "Classification": self.classification(match_field),
            "Actor": self.actor(match_field),
            "GreyNoise_URL": self.url(match_field),
            "VPN": self.vpn_service(match_field),
            "Tor": self.is_tor(match_field),
            "Bot": self.is_bot(match_field),
            "Metadata": self.metadata(match_field),
            "Tags": self.tag_names(match_field),
            "CVEs": self.cve_list(match_field),
        }


class GreyNoiseV3BusinessService(LookupTableMatches):
    """Helper to get GreyNoise V3 Business Service Intelligence for enriched fields"""

    def __init__(self, event, lut_name=None):
        super().__init__()
        if lut_name is None:
            lut_name = _find_greynoise_v3_lut_name(event)
        if lut_name:
            super()._register(event, lut_name)

    def _bsi_lookup(self, match_field: str, *keys):
        return self._lookup(match_field, "business_service_intelligence", *keys)

    def found(self, match_field: str) -> bool:
        return bool(self._bsi_lookup(match_field, "found"))

    def category(self, match_field: str) -> Union[list[str], str]:
        return self._bsi_lookup(match_field, "category")

    def description(self, match_field: str) -> Union[list[str], str]:
        return self._bsi_lookup(match_field, "description")

    def explanation(self, match_field: str) -> Union[list[str], str]:
        return self._bsi_lookup(match_field, "explanation")

    def name(self, match_field: str) -> Union[list[str], str]:
        return self._bsi_lookup(match_field, "name")

    def reference(self, match_field: str) -> Union[list[str], str]:
        return self._bsi_lookup(match_field, "reference")

    def trust_level(self, match_field: str) -> Union[int, list[str], str]:
        return self._bsi_lookup(match_field, "trust_level")

    def last_updated(self, match_field: str) -> datetime.date:
        time = self._bsi_lookup(match_field, "last_updated")
        if not time:
            return None
        try:
            if isinstance(time, Sequence) and not isinstance(time, str):
                if len(time) == 0:
                    return None
                return max(parser.parse(t) for t in time)
            return parser.parse(time)
        except (ValueError, TypeError):
            return None

    def ip_address(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "ip")

    def url(self, match_field: str) -> Union[list[str], str, None]:
        ip_address = self._lookup(match_field, "ip")
        if not ip_address:
            return None
        if isinstance(ip_address, Sequence) and not isinstance(ip_address, str):
            return [f"https://www.greynoise.io/viz/ip/{addr}" for addr in ip_address]
        return f"https://www.greynoise.io/viz/ip/{ip_address}"

    def context(self, match_field: str) -> dict:
        return {
            "Found": self.found(match_field),
            "IP": self.ip_address(match_field),
            "Name": self.name(match_field),
            "Category": self.category(match_field),
            "TrustLevel": self.trust_level(match_field),
            "GreyNoise_URL": self.url(match_field),
        }


def get_greynoise_v3_object(event):
    """Returns a GreyNoiseV3ScannerIntelligence object or None if not available"""
    lut_name = _find_greynoise_v3_lut_name(event)
    if lut_name:
        return GreyNoiseV3ScannerIntelligence(event, lut_name=lut_name)
    return None


def get_greynoise_v3_business_service_object(event):
    """Returns a GreyNoiseV3BusinessService object or None if not available"""
    lut_name = _find_greynoise_v3_lut_name(event)
    if lut_name:
        return GreyNoiseV3BusinessService(event, lut_name=lut_name)
    return None


def greynoise_v3_severity(event, field, default="MEDIUM"):
    """Set severity based on GreyNoise V3 classification and business service intelligence"""
    lut_name = _find_greynoise_v3_lut_name(event)
    if not lut_name:
        return default
    scanner = GreyNoiseV3ScannerIntelligence(event, lut_name=lut_name)
    bsi = GreyNoiseV3BusinessService(event, lut_name=lut_name)

    # If IP is a known business service, lower severity
    if bsi and bsi.found(field):
        return "INFO"

    classification = scanner.classification(field)
    if isinstance(classification, Sequence) and not isinstance(classification, str):
        highest_severity = "INFO"
        for cls in classification:
            severity = greynoise_severity_decode(cls, default)
            if severity_greater_than(severity, highest_severity):
                highest_severity = severity
        return highest_severity

    return greynoise_severity_decode(classification, default)


def greynoise_v3_alert_context(event, field):
    """Build a rich alert context dict from GreyNoise V3 enrichment data."""
    lut_name = _find_greynoise_v3_lut_name(event)
    if not lut_name:
        return {}

    scanner = GreyNoiseV3ScannerIntelligence(event, lut_name=lut_name)
    ctx = scanner.context(field)
    first_seen = scanner.first_seen(field)
    ctx["FirstSeen"] = str(first_seen) if first_seen is not None else None
    last_seen = scanner.last_seen(field)
    ctx["LastSeen"] = str(last_seen) if last_seen is not None else None
    ctx["Spoofable"] = scanner.is_spoofable(field)
    ctx["Organization"] = scanner.organization(field)
    ctx["SourceCountry"] = scanner.source_country(field)
    ctx["ASN"] = scanner.asn(field)
    ctx["OperatingSystem"] = scanner.operating_system(field)
    ctx["ReverseDNS"] = scanner.rev_dns(field)

    bsi = GreyNoiseV3BusinessService(event, lut_name=lut_name)
    if bsi.found(field):
        ctx["BusinessService"] = bsi.context(field)

    return ctx


# Backward-compatible aliases
GreyNoiseSeverityDecode = greynoise_severity_decode  # pylint: disable=invalid-name
SeverityGreaterThan = severity_greater_than  # pylint: disable=invalid-name
GetGreyNoiseV3Object = get_greynoise_v3_object  # pylint: disable=invalid-name
GetGreyNoiseV3BusinessServiceObject = (
    get_greynoise_v3_business_service_object  # pylint: disable=invalid-name
)
GreyNoiseV3Severity = greynoise_v3_severity  # pylint: disable=invalid-name
