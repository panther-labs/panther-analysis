import datetime

from panther_base_helpers import deep_get

class TorExitNodes:
    def __init__(self, event):
        self.exit_nodes = deep_get(event, "p_enrichment", "tor_exit_nodes")

    def ip_address(self, match_field) -> str:
        return deep_get(self.exit_nodes, match_field, "ip")

    def url(self, match_field) -> str:
        today = datetime.datetime.today().strftime('%Y-%m-%d')
        return f"https://metrics.torproject.org/exonerator.html?ip={self.ip_address(match_field)}&timestamp={today}&lang=en"

    def context(self, match_field) -> dict:
        ip = self.ip_address(match_field)
        if ip:
            return {
                "IP": ip,
                "ExoneraTorURL": self.url(match_field),
            }
        else:
            return {}


