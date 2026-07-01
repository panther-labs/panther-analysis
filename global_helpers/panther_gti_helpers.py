# pylint: disable=too-many-public-methods
import datetime
from collections.abc import Sequence
from typing import Union

from dateutil import parser
from panther_base_helpers import severity_greater_than  # re-exported for rule imports
from panther_lookuptable_helpers import LookupTableMatches

# `severity_greater_than` is re-exported above so rules importing it from this
# module continue to work; the canonical definition lives in panther_base_helpers.
_ = severity_greater_than

# Values of `type` on a GTI/VirusTotal IOC that map to a VT GUI path segment
# different from the raw type string.
_GTI_TYPE_TO_URL_SEGMENT = {
    "ip_address": "ip-address",
}


_LEVEL_TO_SEVERITY = {
    "SEVERITY_HIGH": "CRITICAL",
    "SEVERITY_MEDIUM": "HIGH",
    "SEVERITY_LOW": "MEDIUM",
}

_MALICIOUS_COUNT_THRESHOLDS = (
    (10, "HIGH"),
    (3, "MEDIUM"),
    (1, "LOW"),
)


def _severity_from_malicious_count(count: int, default: str) -> str:
    count = count or 0
    for threshold, sev in _MALICIOUS_COUNT_THRESHOLDS:
        if count >= threshold:
            return sev
    return default


def gti_severity_from_verdict(
    threat_severity_level: str, malicious_count: int, default: str = "MEDIUM"
) -> str:
    """Derive a Panther severity from GTI/VirusTotal verdict data.

    - GTI's own `threat_severity_level` is used when present (SEVERITY_HIGH -> CRITICAL,
      SEVERITY_MEDIUM -> HIGH, SEVERITY_LOW -> MEDIUM).
    - Otherwise, fall back to the number of vendors flagging the indicator malicious.
    - Otherwise -> default (MEDIUM).
    """
    level = (threat_severity_level or "").upper()
    if level in _LEVEL_TO_SEVERITY:
        return _LEVEL_TO_SEVERITY[level]
    return _severity_from_malicious_count(malicious_count, default)


# GTI/VirusTotal Enrichment Helpers


def _find_gti_lut_name(event) -> str:
    """Auto-detect the GTI/VirusTotal lookup table name from the event enrichment.

    The LUT name is user-customizable in Panther, so detection is based on the
    presence of VT-distinctive fields ('gti_url' or 'last_analysis_stats') in the
    matched values rather than a fixed name/suffix.
    """
    enrichment = event.deep_get("p_enrichment", default={})
    for lut_name, lut_values in enrichment.items():
        if not hasattr(lut_values, "values"):
            continue
        for match_data in lut_values.values():
            if not hasattr(match_data, "get"):
                continue
            if match_data.get("gti_url") or match_data.get("last_analysis_stats"):
                return lut_name
    return None


class GTIIntelligence(LookupTableMatches):
    """Helper to access GTI/VirusTotal enrichment data for matched indicators."""

    def __init__(self, event, lut_name=None):
        super().__init__()
        if lut_name is None:
            lut_name = _find_gti_lut_name(event)
        if lut_name:
            super()._register(event, lut_name)

    # Identity fields
    def indicator_id(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "id")

    def indicator_type(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "type")

    def type_description(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "type_description")

    def meaningful_name(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "meaningful_name")

    def names(self, match_field: str) -> list:
        names = self._lookup(match_field, "names")
        if not names:
            return []
        if isinstance(names, str):
            return [names]
        return names

    def md5(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "md5")

    def sha1(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "sha1")

    def sha256(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "sha256")

    # Verdict fields
    def reputation(self, match_field: str) -> Union[list[int], int]:
        return self._lookup(match_field, "reputation")

    def gti_confidence_score(self, match_field: str) -> Union[list[int], int]:
        return self._lookup(match_field, "gti_confidence_score")

    def last_analysis_stats(self, match_field: str) -> Union[list[dict], dict]:
        return self._lookup(match_field, "last_analysis_stats")

    def _analysis_stat(self, match_field: str, stat: str) -> Union[list[int], int]:
        stats = self.last_analysis_stats(match_field)
        if stats is None:
            return None
        if isinstance(stats, Sequence) and not isinstance(stats, str):
            return [s.get(stat, 0) if hasattr(s, "get") else 0 for s in stats]
        return stats.get(stat, 0) if hasattr(stats, "get") else 0

    def malicious_count(self, match_field: str) -> Union[list[int], int]:
        return self._analysis_stat(match_field, "malicious")

    def suspicious_count(self, match_field: str) -> Union[list[int], int]:
        return self._analysis_stat(match_field, "suspicious")

    def harmless_count(self, match_field: str) -> Union[list[int], int]:
        return self._analysis_stat(match_field, "harmless")

    def undetected_count(self, match_field: str) -> Union[list[int], int]:
        return self._analysis_stat(match_field, "undetected")

    # Threat classification fields
    def threat_severity_level(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "threat_severity", "threat_severity_level")

    def threat_severity_description(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "threat_severity", "level_description")

    def suggested_threat_label(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "popular_threat_classification", "suggested_threat_label")

    def _threat_classification_values(self, match_field: str, key: str) -> list:
        classification = self._lookup(match_field, "popular_threat_classification", key)
        if not classification:
            return []
        if isinstance(classification, Sequence) and not isinstance(classification, str):
            values = []
            for entry in classification:
                if hasattr(entry, "get"):
                    values.append(entry.get("value"))
            return values
        return []

    def threat_categories(self, match_field: str) -> list:
        return self._threat_classification_values(match_field, "popular_threat_category")

    def threat_names(self, match_field: str) -> list:
        return self._threat_classification_values(match_field, "popular_threat_name")

    def tags(self, match_field: str) -> list:
        tags = self._lookup(match_field, "tags")
        if not tags:
            return []
        if isinstance(tags, str):
            return [tags]
        return tags

    def tags_string(self, match_field: str, limit: int = 10) -> str:
        return ", ".join(self.tags(match_field)[:limit])

    def capabilities_tags(self, match_field: str) -> list:
        tags = self._lookup(match_field, "capabilities_tags")
        if not tags:
            return []
        if isinstance(tags, str):
            return [tags]
        return tags

    def categories(self, match_field: str) -> Union[list, dict]:
        return self._lookup(match_field, "categories")

    # Network/infrastructure fields (domain, IP, and URL IOCs)
    def country(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "country")

    def as_owner(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "as_owner")

    def asn(self, match_field: str) -> Union[list[int], int]:
        return self._lookup(match_field, "asn")

    def network(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "network")

    def registrar(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "registrar")

    def title(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "title")

    def url(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "url")

    def last_final_url(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "last_final_url")

    # Timestamp fields
    def _parse_time(self, match_field: str, key: str, use_max: bool = False):
        time = self._lookup(match_field, key)
        if not time:
            return None
        try:
            if isinstance(time, Sequence) and not isinstance(time, str):
                if len(time) == 0:
                    return None
                return (max if use_max else min)(parser.parse(t) for t in time)
            return parser.parse(time)
        except (ValueError, TypeError):
            return None

    def creation_date(self, match_field: str) -> datetime.date:
        return self._parse_time(match_field, "creation_date")

    def first_submission_date(self, match_field: str) -> datetime.date:
        return self._parse_time(match_field, "first_submission_date")

    def last_analysis_date(self, match_field: str) -> datetime.date:
        return self._parse_time(match_field, "last_analysis_date", use_max=True)

    def last_modification_date(self, match_field: str) -> datetime.date:
        return self._parse_time(match_field, "last_modification_date", use_max=True)

    # Links
    def gti_link(self, match_field: str) -> Union[list[str], str, None]:
        link = self._lookup(match_field, "gti_url")
        if link:
            return link

        indicator_id = self.indicator_id(match_field)
        indicator_type = self.indicator_type(match_field)
        if not indicator_id or not indicator_type:
            return None

        def _build(ioc_id: str, ioc_type: str) -> str:
            segment = _GTI_TYPE_TO_URL_SEGMENT.get(ioc_type, ioc_type)
            return f"https://www.virustotal.com/gui/{segment}/{ioc_id}"

        if isinstance(indicator_id, Sequence) and not isinstance(indicator_id, str):
            return [
                _build(ioc_id, ioc_type) for ioc_id, ioc_type in zip(indicator_id, indicator_type)
            ]
        return _build(indicator_id, indicator_type)

    def context(self, match_field: str) -> dict:
        return {
            "Indicator": self.indicator_id(match_field),
            "IndicatorType": self.indicator_type(match_field),
            "Names": self.names(match_field),
            "Reputation": self.reputation(match_field),
            "MaliciousCount": self.malicious_count(match_field),
            "SuspiciousCount": self.suspicious_count(match_field),
            "ThreatSeverity": self.threat_severity_level(match_field),
            "SuggestedThreatLabel": self.suggested_threat_label(match_field),
            "Tags": self.tags(match_field),
            "GTI_URL": self.gti_link(match_field),
        }


def get_gti_object(event):
    """Returns a GTIIntelligence object or None if not available."""
    lut_name = _find_gti_lut_name(event)
    if lut_name:
        return GTIIntelligence(event, lut_name=lut_name)
    return None


def gti_severity(event, field, default="MEDIUM"):
    """Set severity based on GTI/VirusTotal verdict data (threat severity, detections)."""
    lut_name = _find_gti_lut_name(event)
    if not lut_name:
        return default
    gti = GTIIntelligence(event, lut_name=lut_name)

    threat_severity_level = gti.threat_severity_level(field)
    malicious_count = gti.malicious_count(field)

    if isinstance(threat_severity_level, Sequence) and not isinstance(threat_severity_level, str):
        # Multiple matches — return highest severity across all
        highest = "INFO"
        for level, count in zip(threat_severity_level, malicious_count):
            sev = gti_severity_from_verdict(level, count, default)
            if severity_greater_than(sev, highest):
                highest = sev
        return highest

    return gti_severity_from_verdict(threat_severity_level, malicious_count, default)


def gti_alert_context(event, field):
    """Build a rich alert context dict from GTI/VirusTotal enrichment data."""
    lut_name = _find_gti_lut_name(event)
    if not lut_name:
        return {}
    gti = GTIIntelligence(event, lut_name=lut_name)
    ctx = gti.context(field)
    ctx["ThreatCategories"] = gti.threat_categories(field)
    ctx["ThreatNames"] = gti.threat_names(field)
    first_submission = gti.first_submission_date(field)
    ctx["FirstSubmissionDate"] = str(first_submission) if first_submission is not None else None
    last_analysis = gti.last_analysis_date(field)
    ctx["LastAnalysisDate"] = str(last_analysis) if last_analysis is not None else None
    return ctx
