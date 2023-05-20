from panther_base_helpers import deep_get

# pylint: disable=R0903 (too-few-public-methods)
class LookupTableMatches:
    def _register(self, event, lookuptable_name: str):
        # pylint: disable=W0201 (attribute-defined-outside-init)
        self.lut_matches = deep_get(event, "p_enrichment", lookuptable_name)

    def _lookup(self, match_field: str, *keys) -> list or str:
        match = deep_get(self.lut_matches, match_field)
        if not match:
            return None
        if isinstance(match, list):
            return [deep_get(match_value, *keys) if match_value else None for match_value in match]
        return deep_get(match, *keys)
