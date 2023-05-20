import datetime

from panther_lookuptable_helpers import LookupTableMatches


class TorExitNodes(LookupTableMatches):
    def __init__(self, event):
        super()._register(event, "tor_exit_nodes")

    def ip_address(self, match_field) -> list or str:
        """Enrich an ip address"""
        return self._lookup(match_field, "ip")

    def url(self, match_field) -> list or str:
        """Return link to Tor database"""
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        ip_address = self.ip_address(match_field)
        if isinstance(ip_address, list):
            return [
                # pylint: disable=0301 (line-too-long)
                f"https://metrics.torproject.org/exonerator.html?ip={list_ip_address}&timestamp={today}&lang=en"
                for list_ip_address in ip_address
            ]
        # pylint: disable=line-too-long
        return f"https://metrics.torproject.org/exonerator.html?ip={ip_address}&timestamp={today}&lang=en"

    def context(self, match_field) -> dict:
        """Create a context dictionary"""
        ip_address = self.ip_address(match_field)
        if ip_address:
            return {
                "IP": ip_address,
                "ExoneraTorURL": self.url(match_field),
            }
        return {}
