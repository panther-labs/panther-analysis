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
        return {
            "IP": self.ip_address(match_field),
            "ExoneraTorURL": self.url(match_field),
        }

if __name__ == "__main__":
    torExitNodes = TorExitNodes({
        "p_enrichment": {
              "tor_exit_nodes":  {
                    "some_ip_field": {
                           "ip": "146.59.233.33"
                        }
                  }
            }
        })
    print(torExitNodes.ip_address("some_ip_field"))
    print(torExitNodes.url("some_ip_field"))
    print(torExitNodes.context("some_ip_field"))
