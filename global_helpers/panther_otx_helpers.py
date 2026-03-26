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


def severity_greater_than(sev1: str, sev2: str) -> bool:
    return _SEVERITIES.get(sev1, -1) > _SEVERITIES.get(sev2, -1)


def otx_severity_from_pulse(adversary: str, malware_families: list, default: str = "MEDIUM") -> str:
    """Derive a Panther severity from OTX pulse metadata.

    - Has a named adversary AND malware families → CRITICAL
    - Has malware families → HIGH
    - Has a named adversary → HIGH
    - Otherwise → default (MEDIUM)
    """
    has_adversary = bool(adversary)
    has_malware = bool(malware_families)
    if has_adversary and has_malware:
        return "CRITICAL"
    if has_malware or has_adversary:
        return "HIGH"
    return default


# OTX Pulse Enrichment Helpers


def _find_otx_lut_name(event) -> str:
    """Auto-detect the OTX lookup table name from the event enrichment.

    The LUT name is user-customizable in Panther but always ends with '_otx'.
    OTX data is identified by the presence of 'indicator_type' in the values.
    """
    enrichment = event.deep_get("p_enrichment", default={})
    for lut_name in enrichment.keys():
        if not lut_name.endswith("_otx"):
            continue
        for match_data in enrichment.get(lut_name, {}).values():
            if hasattr(match_data, "get") and match_data.get("indicator_type"):
                return lut_name
    return None


class OTXPulseIntelligence(LookupTableMatches):
    """Helper to access OTX Pulse enrichment data for matched indicators."""

    def __init__(self, event, lut_name=None):
        super().__init__()
        if lut_name is None:
            lut_name = _find_otx_lut_name(event)
        if lut_name:
            super()._register(event, lut_name)

    # Indicator fields
    def indicator(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "indicator")

    def indicator_type(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "indicator_type")

    def indicator_created(self, match_field: str) -> datetime.date:
        time = self._lookup(match_field, "indicator_created")
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

    def indicator_expiration(self, match_field: str) -> datetime.date:
        time = self._lookup(match_field, "indicator_expiration")
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

    # Pulse metadata
    def pulse_id(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "id")

    def name(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "name")

    def description(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "description")

    def created(self, match_field: str) -> datetime.date:
        time = self._lookup(match_field, "created")
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

    def modified(self, match_field: str) -> datetime.date:
        time = self._lookup(match_field, "modified")
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

    def tags(self, match_field: str) -> list:
        tags = self._lookup(match_field, "tags")
        if not tags:
            return []
        if isinstance(tags, str):
            return [tags]
        return tags

    def tags_string(self, match_field: str, limit: int = 10) -> str:
        return ", ".join(self.tags(match_field)[:limit])

    def industries(self, match_field: str) -> list:
        industries = self._lookup(match_field, "industries")
        if not industries:
            return []
        if isinstance(industries, str):
            return [industries]
        return industries

    def malware_families(self, match_field: str) -> list:
        families = self._lookup(match_field, "malware_families")
        if not families:
            return []
        if isinstance(families, str):
            return [families]
        return families

    def malware_families_string(self, match_field: str, limit: int = 10) -> str:
        return ", ".join(self.malware_families(match_field)[:limit])

    def references(self, match_field: str) -> list:
        refs = self._lookup(match_field, "references")
        if not refs:
            return []
        if isinstance(refs, str):
            return [refs]
        return refs

    def tlp(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "tlp")

    def adversary(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "adversary")

    def target_countries(self, match_field: str) -> list:
        countries = self._lookup(match_field, "target_countries")
        if not countries:
            return []
        if isinstance(countries, str):
            return [countries]
        return countries

    def attack_ids(self, match_field: str) -> list:
        ids = self._lookup(match_field, "attack_ids")
        if not ids:
            return []
        if isinstance(ids, str):
            return [ids]
        return ids

    def attack_ids_string(self, match_field: str, limit: int = 10) -> str:
        return ", ".join(self.attack_ids(match_field)[:limit])

    def url(self, match_field: str) -> Union[list[str], str, None]:
        pulse_id = self._lookup(match_field, "id")
        if not pulse_id:
            return None
        if isinstance(pulse_id, Sequence) and not isinstance(pulse_id, str):
            return [f"https://otx.alienvault.com/pulse/{pid}" for pid in pulse_id]
        return f"https://otx.alienvault.com/pulse/{pulse_id}"

    def context(self, match_field: str) -> dict:
        return {
            "Indicator": self.indicator(match_field),
            "IndicatorType": self.indicator_type(match_field),
            "PulseName": self.name(match_field),
            "Adversary": self.adversary(match_field),
            "MalwareFamilies": self.malware_families(match_field),
            "Tags": self.tags(match_field),
            "Industries": self.industries(match_field),
            "TargetCountries": self.target_countries(match_field),
            "AttackIDs": self.attack_ids(match_field),
            "TLP": self.tlp(match_field),
            "OTX_URL": self.url(match_field),
        }


def get_otx_object(event):
    """Returns an OTXPulseIntelligence object or None if not available."""
    lut_name = _find_otx_lut_name(event)
    if lut_name:
        return OTXPulseIntelligence(event, lut_name=lut_name)
    return None


def otx_severity(event, field, default="MEDIUM"):
    """Set severity based on OTX pulse metadata (adversary, malware families)."""
    lut_name = _find_otx_lut_name(event)
    if not lut_name:
        return default
    otx = OTXPulseIntelligence(event, lut_name=lut_name)

    adversary = otx.adversary(field)
    malware_families = otx.malware_families(field)

    if isinstance(adversary, Sequence) and not isinstance(adversary, str):
        # Multiple matches — return highest severity across all
        highest = "INFO"
        for adv, mal in zip(adversary, malware_families):
            sev = otx_severity_from_pulse(adv, mal, default)
            if severity_greater_than(sev, highest):
                highest = sev
        return highest

    return otx_severity_from_pulse(adversary, malware_families, default)


def otx_alert_context(event, field):
    """Build a rich alert context dict from OTX enrichment data."""
    lut_name = _find_otx_lut_name(event)
    if not lut_name:
        return {}
    otx = OTXPulseIntelligence(event, lut_name=lut_name)
    ctx = otx.context(field)
    ctx["PulseID"] = otx.pulse_id(field)
    ctx["Description"] = otx.description(field)
    ctx["References"] = otx.references(field)
    indicator_created = otx.indicator_created(field)
    ctx["IndicatorCreated"] = str(indicator_created) if indicator_created is not None else None
    indicator_expiration = otx.indicator_expiration(field)
    ctx["IndicatorExpiration"] = (
        str(indicator_expiration) if indicator_expiration is not None else None
    )
    pulse_created = otx.created(field)
    ctx["PulseCreated"] = str(pulse_created) if pulse_created is not None else None
    pulse_modified = otx.modified(field)
    ctx["PulseModified"] = str(pulse_modified) if pulse_modified is not None else None
    return ctx
