from panther_base_helpers import deep_get

ENRICHMENT_KEY = "p_enrichment"

# pylint: disable=too-few-public-methods
class LookupTableMatches:
    def _register(self, event, lookuptable_name: str):
        # pylint: disable=attribute-defined-outside-init
        self.lut_matches = deep_get(event, ENRICHMENT_KEY, lookuptable_name)

    def _lookup(self, match_field: str, *keys) -> list or str:
        match = deep_get(self.lut_matches, match_field)
        if not match:
            return None
        if isinstance(match, list):
            return [deep_get(match_value, *keys) if match_value else None for match_value in match]
        return deep_get(match, *keys)

    def enrichments_by_pmatch(self, event, p_match: str) -> dict:
        matched_items = {}
        for enrichment_type in deep_get(event, ENRICHMENT_KEY, default={}).keys():
            for en_values in deep_get(event, ENRICHMENT_KEY, enrichment_type, default={}).values():
                if isinstance(en_values, list):
                    for val in en_values:
                        if deep_get(val, "p_match", default="") == p_match:
                            matched_items[enrichment_type] = val
                if isinstance(en_values, dict):
                    if deep_get(en_values, "p_match", default="") == p_match:
                        matched_items[enrichment_type] = en_values
        return matched_items
