#!/usr/bin/env python
# Unit tests for functions inside global_helpers

import datetime
import os
import sys
import unittest

# pipenv run does the right thing, but IDE based debuggers may fail to import
#   so noting, we append this directory to sys.path
sys.path.append(os.path.dirname(__file__))

import panther_greynoise_helpers as p_greynoise_h  # pylint: disable=C0413
import panther_tor_helpers as p_tor_h  # pylint: disable=C0413


class TestTorExitNodes(unittest.TestCase):

    event = {"p_enrichment": {"tor_exit_nodes": {"foo": {"ip": "1.2.3.4"}}}}

    # match against array field
    event_list = {
        "p_enrichment": {
            "tor_exit_nodes": {"p_any_ip_addresses": [{"ip": "1.2.3.4"}, {"ip": "1.2.3.5"}]}
        }
    }

    def test_ip_address_not_found(self):
        """Should not find anything"""
        tor_exit_nodes = p_tor_h.TorExitNodes({})
        ip_address = tor_exit_nodes.ip_address("foo")
        self.assertEqual(ip_address, None)

    def test_ip_address__found(self):
        """Should find enrichment"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event)
        ip_address = tor_exit_nodes.ip_address("foo")
        self.assertEqual(ip_address, "1.2.3.4")

    def test_ip_address__found_list(self):
        """Should find enrichment list"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event_list)
        ip_address_list = tor_exit_nodes.ip_address("p_any_ip_addresses")
        self.assertEqual(ip_address_list, ["1.2.3.4", "1.2.3.5"])

    def test_url(self):
        """url generation"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event)
        url = tor_exit_nodes.url("foo")
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        # pylint: disable=line-too-long
        self.assertEqual(
            url,
            f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.4&timestamp={today}&lang=en",
        )

    def test_url_list(self):
        """url generation list"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event_list)
        urls = tor_exit_nodes.url("p_any_ip_addresses")
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        # pylint: disable=line-too-long
        self.assertEqual(
            urls,
            [
                f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.4&timestamp={today}&lang=en",
                f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.5&timestamp={today}&lang=en",
            ],
        )

    def test_context(self):
        """context generation"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event)
        context = tor_exit_nodes.context("foo")
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        self.assertEqual(
            context,
            {
                "IP": "1.2.3.4",
                # pylint: disable=line-too-long
                "ExoneraTorURL": f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.4&timestamp={today}&lang=en",
            },
        )


class TestGreyNoiseBasic(unittest.TestCase):

    event = {
        "p_enrichment": {
            "greynoise_noise_basic": {
                "ClientIP": {
                    "actor": "unknown",
                    "classification": "malicious",
                    "ip": "142.93.204.250",
                }
            }
        }
    }

    def test_subscription_level(self):
        """Should be basic"""
        noise = p_greynoise_h.GreyNoiseBasic({})
        self.assertEqual(noise.subscription_level(), "basic")

    def test_ip_address_not_found(self):
        """Should not find anything"""
        noise = p_greynoise_h.GreyNoiseBasic({})
        ip_address = noise.ip_address("foo")
        self.assertEqual(ip_address, None)

    def test_ip_address__found(self):
        """Should find enrichment"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        ip_address = noise.ip_address("ClientIP")
        self.assertEqual(ip_address, "142.93.204.250")

    def test_classification(self):
        """Should classify as malicious"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        classification = noise.classification("ClientIP")
        self.assertEqual(classification, "malicious")

    def test_actor(self):
        """Should have unknown actor"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        actor = noise.actor("ClientIP")
        self.assertEqual(actor, "unknown")

    def test_url(self):
        """Should have url"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        url = noise.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_context(self):
        """context generation"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        context = noise.context("ClientIP")
        self.assertEqual(
            context,
            {
                "Actor": "unknown",
                "Classification": "malicious",
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250",
            },
        )


class TestGreyNoiseAdvanced(unittest.TestCase):

    event = {
        "p_enrichment": {
            "greynoise_noise_advanced": {
                "ClientIP": {
                    "actor": "unknown",
                    "bot": False,
                    "classification": "malicious",
                    "cve": ["cve1244", "cve4567"],
                    "first_seen": "2022-03-19",
                    "ip": "142.93.204.250",
                    "last_seen_timestamp": "2022-04-06",
                    "metadata": {
                        "asn": "AS14061",
                        "category": "hosting",
                        "city": "North Bergen",
                        "country": "United States",
                        "country_code": "US",
                        "organization": "DigitalOcean, LLC",
                        "os": "Linux 2.2-3.x",
                        "rdns": "",
                        "region": "New Jersey",
                        "tor": False,
                    },
                    "raw_data": {
                        "hassh": [],
                        "ja3": [],
                        "scan": [{"port": 23, "protocol": "TCP"}],
                        "web": {},
                    },
                    "seen": True,
                    "spoofable": False,
                    "tags": ["Mirai", "ZMap Client"],
                    "vpn": False,
                    "vpn_service": "N/A",
                }
            }
        }
    }

    def test_subscription_level(self):
        """Should be advanced"""
        noise = p_greynoise_h.GreyNoiseAdvanced({})
        self.assertEqual(noise.subscription_level(), "advanced")

    def test_ip_address_not_found(self):
        """Should not find anything"""
        noise = p_greynoise_h.GreyNoiseAdvanced({})
        ip_address = noise.ip_address("foo")
        self.assertEqual(ip_address, None)

    def test_ip_address__found(self):
        """Should find enrichment"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        ip_address = noise.ip_address("ClientIP")
        self.assertEqual(ip_address, "142.93.204.250")

    def test_classification(self):
        """Should classify as malicious"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        classification = noise.classification("ClientIP")
        self.assertEqual(classification, "malicious")

    def test_actor(self):
        """Should have unknown actor"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        actor = noise.actor("ClientIP")
        self.assertEqual(actor, "unknown")

    def test_url(self):
        """Should have url"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        url = noise.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_is_bot(self):
        """Should be bot"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_bot = noise.is_bot("ClientIP")
        self.assertEqual(is_bot, False)

    def test_cve_string(self):
        """Should have cve string"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        cve_string = noise.cve_string("ClientIP")
        self.assertEqual(cve_string, "cve1244 cve4567")

    def test_cve_list(self):
        """Should have cve list"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        cve_list = noise.cve_list("ClientIP")
        self.assertEqual(cve_list, ["cve1244", "cve4567"])

    def test_first_seen(self):
        """Should have first seen"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        first_seen = noise.first_seen("ClientIP")
        self.assertEqual(first_seen, datetime.datetime(2022, 3, 19, 0, 0))

    def test_last_seen(self):
        """Should have last seen"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        last_seen = noise.last_seen("ClientIP")
        self.assertEqual(last_seen, datetime.datetime(2022, 4, 6, 0, 0))

    def test_asn(self):
        """Should have asn"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        asn = noise.asn("ClientIP")
        self.assertEqual(asn, "AS14061")

    def test_category(self):
        """Should have catgeory"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        category = noise.category("ClientIP")
        self.assertEqual(category, "hosting")

    def test_city(self):
        """Should have city"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        city = noise.city("ClientIP")
        self.assertEqual(city, "North Bergen")

    def test_country(self):
        """Should have city"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        country = noise.country("ClientIP")
        self.assertEqual(country, "United States")

    def test_country_code(self):
        """Should have city"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        country_code = noise.country_code("ClientIP")
        self.assertEqual(country_code, "US")

    def test_organization(self):
        """Should have organization"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        organization = noise.organization("ClientIP")
        self.assertEqual(organization, "DigitalOcean, LLC")

    def test_operating_system(self):
        """Should have os"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        os = noise.operating_system("ClientIP")
        self.assertEqual(os, "Linux 2.2-3.x")

    def test_region(self):
        """Should have region"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        region = noise.region("ClientIP")
        self.assertEqual(region, "New Jersey")

    def test_is_tor(self):
        """Should not have tor"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_tor = noise.is_tor("ClientIP")
        self.assertEqual(is_tor, False)

    def test_rev_dns(self):
        """Should not have rev dns"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        rev_dns = noise.rev_dns("ClientIP")
        self.assertEqual(rev_dns, "")

    def test_is_spoofable(self):
        """Should not be spoofable"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_spoofable = noise.is_spoofable("ClientIP")
        self.assertEqual(is_spoofable, False)

    def test_tags_string(self):
        """Should have tags string"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        tags_string = noise.tags_string("ClientIP")
        self.assertEqual(tags_string, "Mirai ZMap Client")

    def test_tags_list(self):
        """Should have tags list"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        tags_list = noise.tags_list("ClientIP")
        self.assertEqual(tags_list, ["Mirai", "ZMap Client"])

    def test_is_vpn(self):
        """Should not be vpn"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_vpn = noise.is_vpn("ClientIP")
        self.assertEqual(is_vpn, False)

    def test_vpn_service(self):
        """Should not be vpn service"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        vpn_service = noise.vpn_service("ClientIP")
        self.assertEqual(vpn_service, "N/A")

    def test_metadata(self):
        """Should have metadata"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        metadata = noise.metadata("ClientIP")
        self.assertEqual(
            metadata,
            {
                "asn": "AS14061",
                "category": "hosting",
                "city": "North Bergen",
                "country": "United States",
                "country_code": "US",
                "organization": "DigitalOcean, LLC",
                "os": "Linux 2.2-3.x",
                "rdns": "",
                "region": "New Jersey",
                "tor": False,
            },
        )

    def test_context(self):
        """context generation"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        context = noise.context("ClientIP")
        self.assertEqual(
            context,
            {
                "Actor": "unknown",
                "Classification": "malicious",
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250",
                "Metadata": {
                    "asn": "AS14061",
                    "category": "hosting",
                    "city": "North Bergen",
                    "country": "United States",
                    "country_code": "US",
                    "organization": "DigitalOcean, LLC",
                    "os": "Linux 2.2-3.x",
                    "rdns": "",
                    "region": "New Jersey",
                    "tor": False,
                },
                "VPN": "N/A",
                "Tags": ["Mirai", "ZMap Client"],
                "CVE": ["cve1244", "cve4567"],
            },
        )


class TestRIOTBasic(unittest.TestCase):

    event = {
        "p_enrichment": {
            "greynoise_riot_basic": {
                "ClientIP": {
                    "ip_cidr": "142.93.204.250/32",
                    "provider": {"name": "foo"},
                    "scan_time": "2023-05-12 05:11:04.679962983",
                }
            }
        }
    }

    def test_subscription_level(self):
        """Should be basic"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic({})
        self.assertEqual(riot.subscription_level(), "basic")

    def test_is_riot(self):
        """Should be riot"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        is_riot = riot.is_riot("ClientIP")
        self.assertEqual(is_riot, True)

    def test_ip_address(self):
        """Should have ip address"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        cidr = riot.ip_address("ClientIP")
        self.assertEqual(cidr, "142.93.204.250/32")

    def test_name(self):
        """Should have name"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        name = riot.name("ClientIP")
        self.assertEqual(name, "foo")

    def test_url(self):
        """Should have url"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        url = riot.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_last_updated(self):
        """Should have last_updated"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        last_udpated = riot.last_updated("ClientIP")
        self.assertEqual(last_udpated, datetime.datetime(2023, 5, 12, 5, 11, 4, 679962))

    def test_context(self):
        """Should have context"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        context = riot.context("ClientIP")
        self.assertEqual(
            context,
            {
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250/32",
                "Is_RIOT": True,
                "Name": "foo",
            },
        )


class TestRIOTAdvanced(unittest.TestCase):

    event = {
        "p_enrichment": {
            "greynoise_riot_advanced": {
                "ClientIP": {
                    "ip_cidr": "142.93.204.250/32",
                    "provider": {
                        "name": "foo",
                        "category": "cloud",
                        "description": "some cloud",
                        "explanation": "because",
                        "reference": "my brother",
                        "trust_level": "1",
                    },
                    "scan_time": "2023-05-12 05:11:04.679962983",
                }
            }
        }
    }

    # for testing array matches
    event_list = {
        "p_enrichment": {
            "greynoise_riot_advanced": {
                "p_any_ip_addresses": [
                    {
                        "ip_cidr": "142.93.204.250/32",
                        "provider": {
                            "name": "foo",
                            "category": "cloud",
                            "description": "some cloud",
                            "explanation": "because",
                            "reference": "my brother",
                            "trust_level": "1",
                        },
                        "scan_time": "2023-05-12 05:11:04.679962983",
                    },
                    {
                        "ip_cidr": "142.93.204.128/32",
                        "provider": {
                            "name": "bar",
                            "category": "cdn",
                            "description": "some some cdn",
                            "explanation": "because",
                            "reference": "my brother",
                            "trust_level": "2",
                        },
                        "scan_time": "2023-05-11 05:11:04.679962983",
                    },
                ]
            }
        }
    }

    def test_subscription_level(self):
        """Should be advanced"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced({})
        self.assertEqual(riot.subscription_level(), "advanced")

    def test_is_riot(self):
        """Should be riot"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        is_riot = riot.is_riot("ClientIP")
        self.assertEqual(is_riot, True)

    def test_ip_address(self):
        """Should have ip address"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        cidr = riot.ip_address("ClientIP")
        self.assertEqual(cidr, "142.93.204.250/32")

    def test_name(self):
        """Should have name"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        name = riot.name("ClientIP")
        self.assertEqual(name, "foo")

    def test_url(self):
        """Should have url"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        url = riot.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_last_updated(self):
        """Should have last_updated"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        last_udpated = riot.last_updated("ClientIP")
        self.assertEqual(last_udpated, datetime.datetime(2023, 5, 12, 5, 11, 4, 679962))

    def test_last_updated_list(self):
        """Should have last_updated (list)"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event_list)
        last_udpated = riot.last_updated("p_any_ip_addresses")
        self.assertEqual(last_udpated, datetime.datetime(2023, 5, 12, 5, 11, 4, 679962))

    def test_description(self):
        """Should have description"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        desc = riot.description("ClientIP")
        self.assertEqual(desc, "some cloud")

    def test_category(self):
        """Should have category"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        cat = riot.category("ClientIP")
        self.assertEqual(cat, "cloud")

    def test_explanation(self):
        """Should have explanation"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        exp = riot.explanation("ClientIP")
        self.assertEqual(exp, "because")

    def test_reference(self):
        """Should have reference"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        ref = riot.reference("ClientIP")
        self.assertEqual(ref, "my brother")

    def test_trust_level(self):
        """Should have trust_level"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        tl = riot.trust_level("ClientIP")
        self.assertEqual(tl, "1")

    def test_trust_level_list(self):
        """Should have trust_level (list)"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event_list)
        levels = riot.trust_level("p_any_ip_addresses")
        self.assertEqual(levels, ["1", "2"])

    def test_context(self):
        """Should have context"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        context = riot.context("ClientIP")
        self.assertEqual(
            context,
            {
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250/32",
                "Is_RIOT": True,
                "Name": "foo",
                "Provider Data": {
                    "name": "foo",
                    "category": "cloud",
                    "description": "some cloud",
                    "explanation": "because",
                    "reference": "my brother",
                    "trust_level": "1",
                },
            },
        )


# --------------------------
if __name__ == "__main__":
    unittest.main()
