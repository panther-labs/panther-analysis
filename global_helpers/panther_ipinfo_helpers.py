from typing import Union

from panther_base_helpers import deep_get
from panther_lookuptable_helpers import LookupTableMatches

IPINFO_LOCATION_LUT_NAME = "ipinfo_location"
IPINFO_ASN_LUT_NAME = "ipinfo_asn"
IPINFO_PRIVACY_LUT_NAME = "ipinfo_privacy"


class PantherIPInfoException(Exception):
    ...


class IPInfoLocation(LookupTableMatches):
    """Helper to get IPInfo location information for enriched fields"""

    def __init__(self, event):
        super().__init__()
        super()._register(event, IPINFO_LOCATION_LUT_NAME)

    def city(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "city")

    def country(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "country")

    def latitude(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "lat")

    def longitude(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "lng")

    def postal_code(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "postal_code")

    def region(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "region")

    def region_code(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "region_code")

    def timezone(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "timezone")

    def context(self, match_field: str) -> object:
        return {
            "City": self.city(match_field),
            "Country": self.country(match_field),
            "Latitude": self.latitude(match_field),
            "Longitude": self.longitude(match_field),
            "PostalCode": self.postal_code(match_field),
            "Region": self.region(match_field),
            "RegionCode": self.region_code(match_field),
            "Timezone": self.timezone(match_field),
        }


class IPInfoASN(LookupTableMatches):
    """Helper to get IPInfo ASN information for enriched fields"""

    def __init__(self, event):
        super().__init__()
        super()._register(event, IPINFO_ASN_LUT_NAME)

    def asn(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "asn")

    def domain(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "domain")

    def name(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "name")

    def route(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "route")

    def type(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "type")

    def context(self, match_field: str) -> object:
        return {
            "ASN": self.asn(match_field),
            "Domain": self.domain(match_field),
            "Name": self.name(match_field),
            "Route": self.route(match_field),
            "Type": self.type(match_field),
        }


class IPInfoPrivacy(LookupTableMatches):
    """Helper to get IPInfo Privacy information for enriched fields"""

    def __init__(self, event):
        super().__init__()
        super()._register(event, IPINFO_PRIVACY_LUT_NAME)

    def hosting(self, match_field: str) -> bool or list:
        return self._lookup(match_field, "hosting")

    def proxy(self, match_field: str) -> bool or list:
        return self._lookup(match_field, "proxy")

    def tor(self, match_field: str) -> bool or list:
        return self._lookup(match_field, "tor")

    def vpn(self, match_field: str) -> bool or list:
        return self._lookup(match_field, "vpn")

    def relay(self, match_field: str) -> bool or list:
        return self._lookup(match_field, "relay")

    def service(self, match_field: str) -> Union[list[str], str]:
        return self._lookup(match_field, "service")

    def context(self, match_field: str) -> object:
        return {
            "Hosting": self.hosting(match_field),
            "Proxy": self.proxy(match_field),
            "Tor": self.tor(match_field),
            "VPN": self.vpn(match_field),
            "Relay": self.relay(match_field),
            "Service": self.service(match_field),
        }


def get_ipinfo_location(event):
    """Returns an IPInfoLocation object for the event or None if it is not available"""
    if deep_get(event, "p_enrichment", IPINFO_LOCATION_LUT_NAME):
        return IPInfoLocation(event)
    return None


def get_ipinfo_asn(event):
    """Returns an IPInfoASN object for the event or None if it is not available"""
    if deep_get(event, "p_enrichment", IPINFO_ASN_LUT_NAME):
        return IPInfoASN(event)
    return None


def get_ipinfo_privacy(event):
    """Returns an IPInfoPrivacy object for the event or None if it is not available"""
    if deep_get(event, "p_enrichment", IPINFO_PRIVACY_LUT_NAME):
        return IPInfoPrivacy(event)
    return None


def geoinfo_from_ip(event, match_field: str):
    """Returns a dictionary with geolocation information that is the same format as
    panther_oss_helper.geoinfo_from_ip() with the following differences:

    - instead of providing the ip, you must provide the event and the match_field
    - the fields "hostname" and "anycast" are not included in the return object
    """
    location = get_ipinfo_location(event)
    asn = get_ipinfo_asn(event)
    if location is None or asn is None:
        raise PantherIPInfoException(
            "Please enable both IPInfo Location and ASN Enrichment Providers"
        )

    if (
        deep_get(asn.lut_matches, match_field) is None
        or deep_get(location.lut_matches, match_field) is None
    ):
        raise PantherIPInfoException(
            f"IPInfo is not configured on the provided match_field: {match_field}"
        )

    return {
        "ip": event.get(match_field),
        "city": location.city(match_field),
        "region": location.region(match_field),
        "country": location.country(match_field),
        "loc": f"{location.latitude(match_field)},{location.longitude(match_field)}",
        "org": f"{asn.asn(match_field)} {asn.name(match_field)}",
        "postal": location.postal_code(match_field),
        "timezone": location.timezone(match_field),
    }
