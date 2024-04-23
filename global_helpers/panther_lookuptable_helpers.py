from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Optional, Union

from panther_base_helpers import deep_get
from panther_core import PantherEvent

ENRICHMENT_KEY = "p_enrichment"
IGNORE_ENRICHMENTS = "p_any_"


# pylint: disable=too-few-public-methods
class LookupTableMatches:
    lut_matches: Optional[PantherEvent]
    _p_matched: Mapping[str, Mapping[str, Any]]

    def __init__(self) -> None:
        self.lut_matches = None
        self._p_matched = {}

    def _register(self, event: PantherEvent, lookuptable_name: str) -> None:
        self.lut_matches = deep_get(event, ENRICHMENT_KEY, lookuptable_name)

    def _lookup(self, match_field: str, *keys: str) -> Union[list[Any], Any]:
        if self.lut_matches is None:
            raise ValueError("Must call _register before _lookup")

        match = deep_get(self.lut_matches, match_field)
        if not match:
            return None
        if isinstance(match, Sequence) and not isinstance(match, str):
            return [deep_get(match_value, *keys) if match_value else None for match_value in match]
        return deep_get(match, *keys)

    @property
    def p_matched(self) -> Mapping[str, Mapping[str, Any]]:
        return self._p_matched

    def p_matches(self, event: PantherEvent, p_match: str = "") -> Mapping[str, Mapping[str, Any]]:
        """Collect enrichments by searching for a value match in the p_match field

        Parameters:
        event (dict): the original log event, as passed to rule(event)
        p_match (str): the value to match on in a p_match field

        Returns:
        dict: All enrichments that hold the searched value in the p_match field

        """
        event = event or {}
        matched_items = {}
        for lut_name in deep_get(event, ENRICHMENT_KEY, default={}):
            if lut_name.startswith(IGNORE_ENRICHMENTS):
                continue
            for en_values in deep_get(event, ENRICHMENT_KEY, lut_name, default={}).values():
                if isinstance(en_values, Sequence):
                    for val in en_values:
                        if deep_get(val, "p_match", default="") == p_match:
                            matched_items[lut_name] = val
                if (
                    isinstance(en_values, Mapping)
                    and deep_get(en_values, "p_match", default="") == p_match
                ):
                    matched_items[lut_name] = en_values
        self._p_matched = matched_items
        return matched_items
