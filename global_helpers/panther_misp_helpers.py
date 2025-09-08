from typing import Union

from panther_lookuptable_helpers import LookupTableMatches

MISP_WARNING_LISTS_LUT_NAME = "misp_warning_lists"


class MISPWarningLists(LookupTableMatches):
    """Helper to get MISP Warning Lists information for enriched fields"""

    def __init__(self, event):
        super().__init__()
        super()._register(event, MISP_WARNING_LISTS_LUT_NAME)

    def warning_lists(self, match_field: str) -> Union[list, None]:
        """Get warning lists for the matched IP"""
        return self._lookup(match_field, "warning_lists")

    def cidr(self, match_field: str) -> Union[list[str], str]:
        """Get CIDR range for the matched IP"""
        return self._lookup(match_field, "cidr")

    def has_warning_list_id(self, source_ip: str, warning_list_id: str) -> bool:
        """Check if the source IP has a specific warning list ID"""
        # MISP data is structured as: MISP Warning Lists -> p_any_ip_addresses -> [array of matches]
        misp_data = self._lookup("p_any_ip_addresses")
        if not misp_data:
            return False

        # misp_data should be a list of IP match objects
        for ip_match in misp_data:
            if ip_match.get("p_match") == source_ip:
                warning_lists = ip_match.get("warning_lists", [])
                if any(wl.get("id") == warning_list_id for wl in warning_lists):
                    return True

        return False


def get_misp_warning_lists(event):
    """Returns a MISPWarningLists object for the event or None if it is not available"""
    if event.deep_get("p_enrichment", MISP_WARNING_LISTS_LUT_NAME):
        return MISPWarningLists(event)
    return None
