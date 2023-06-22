from abc import ABC
from collections.abc import Mapping, Sequence

from panther_base_helpers import deep_get

ENRICHMENT_KEY = "p_enrichment"

# pylint: disable=too-few-public-methods
class LookupTableMatches:
    def __init__(self):
        self.lut_matches = None
        self._p_matched = {}

    def _register(self, event, lookuptable_name: str):
        self.lut_matches = deep_get(event, ENRICHMENT_KEY, lookuptable_name)

    def _lookup(self, match_field: str, *keys) -> list or str:
        match = deep_get(self.lut_matches, match_field)
        if not match:
            return None
        if isinstance(match, list):
            return [deep_get(match_value, *keys) if match_value else None for match_value in match]
        return deep_get(match, *keys)

    @property
    def p_matched(self):
        return self._p_matched

    def p_matches(self, event: dict, p_match: str = "") -> dict:
        """Collect enrichments by searching for a value match in the p_match field

        Parameters:
        event (dict): the original log event, as passed to rule(event)
        p_match (str): the value to match on in a p_match field

        Returns:
        dict: All enrichments that hold the searched value in the p_match field

        """
        event = event or {}
        matched_items = {}
        for lut_name in deep_get(event, ENRICHMENT_KEY, default={}).keys():
            for en_values in deep_get(event, ENRICHMENT_KEY, lut_name, default={}).values():
                if isinstance(en_values, (list, Sequence)):
                    for val in en_values:
                        if deep_get(val, "p_match", default="") == p_match:
                            matched_items[lut_name] = val
                if isinstance(en_values, (dict, ABC, Mapping)):
                    if deep_get(en_values, "p_match", default="") == p_match:
                        matched_items[lut_name] = en_values
        self._p_matched = matched_items
        return matched_items
