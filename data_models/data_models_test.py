import os
import sys
import unittest

from panther_analysis_tool.main import load_analysis, setup_data_models
from panther_core.enriched_event import PantherEvent

# pipenv run does the right thing, but IDE based debuggers may fail to import
#   so noting, we append this directory to sys.path
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.dirname(__file__.replace("data_models", "global_helpers")))

specs, invalid_specs = load_analysis(os.path.dirname(__file__), [], [], [], True)
log_type_to_data_model, invalid_data_models = setup_data_models(specs.data_models)


class TestAWSCloudTrailDataModel(unittest.TestCase):
    data_model = log_type_to_data_model.get("AWS.CloudTrail")

    def test_get_actor_user(self):
        base_event = {
            "p_log_type": "AWS.CloudTrail",
            "userIdentity": {
                "type": "user_type",
                "principalId": "AIDAJ45Q7YFFAREXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/Alice",
                "accountId": "Root",
                "accessKeyId": "",
                "userName": "Root,IAMUser,Directory,Unknown,SAMLUser,WebIdentityUser",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROAIDPPEZS35WEXAMPLE",
                        "arn": "arn:aws:iam::123456789012:role/RoleToBeAssumed",
                        "accountId": "123456789012",
                        "userName": "AssumedRole,Role,FederatedUser",
                    },
                },
            },
            "additionalEventData": {"CredentialType": "PASSWORD", "UserName": "IdentityCenterUser"},
            "sourceIdentity": "AWSService,AWSAccount",
        }

        aws_service_event = PantherEvent(
            {
                "p_log_type": "AWS.CloudTrail",
                "eventType": "AwsServiceEvent",
                "userIdentity": {"invokedBy": "AwsServiceEvent"},
            },
            self.data_model,
        )

        user_types = (
            "Root",
            "IAMUser",
            "Directory",
            "Unknown",
            "SAMLUser",
            "WebIdentityUser",
            "AssumedRole",
            "Role",
            "FederatedUser",
            "IdentityCenterUser",
            "AWSService",
            "AWSAccount",
        )

        for user_type in user_types:
            event = PantherEvent(
                base_event | {"userIdentity": {"type": user_type}}, self.data_model
            )
            self.assertTrue(user_type in event.udm("actor_user"))

        self.assertEqual("AwsServiceEvent", aws_service_event.udm("actor_user"))


class TestSentinelOneDataModel(unittest.TestCase):
    data_model = log_type_to_data_model.get("SentinelOne.DeepVisibility")

    def test_process_creation_fields(self):
        """Test Sigma process creation field mappings"""
        event_data = {
            "p_log_type": "SentinelOne.DeepVisibility",
            "tgt_process_pid": 1234,
            "tgt_process_image_path": "C:\\Windows\\System32\\cmd.exe",
            "tgt_process_displayName": "Command Prompt",
            "tgt_process_publisher": "Microsoft Corporation",
            "tgt_process_cmdline": "cmd.exe /c whoami",
            "tgt_process_user": "DOMAIN\\user",
            "tgt_process_sessionId": "5",
            "tgt_process_integrityLevel": "High",
            "tgt_process_image_md5": "abc123",
            "tgt_process_image_sha1": "def456",
            "tgt_process_image_sha256": "ghi789",
            "src_process_pid": 4567,
            "src_process_image_path": "C:\\Windows\\explorer.exe",
            "src_process_cmdline": "explorer.exe",
        }
        event = PantherEvent(event_data, self.data_model)

        # Test process creation mappings
        self.assertEqual(1234, event.udm("ProcessId"))
        self.assertEqual("C:\\Windows\\System32\\cmd.exe", event.udm("Image"))
        self.assertEqual("Command Prompt", event.udm("Description"))
        self.assertEqual("Command Prompt", event.udm("Product"))
        self.assertEqual("Microsoft Corporation", event.udm("Company"))
        self.assertEqual("cmd.exe /c whoami", event.udm("CommandLine"))
        self.assertEqual("DOMAIN\\user", event.udm("User"))
        self.assertEqual("5", event.udm("TerminalSessionId"))
        self.assertEqual("High", event.udm("IntegrityLevel"))
        self.assertEqual("abc123", event.udm("md5"))
        self.assertEqual("def456", event.udm("sha1"))
        self.assertEqual("ghi789", event.udm("sha256"))
        self.assertEqual(4567, event.udm("ParentProcessId"))
        self.assertEqual("C:\\Windows\\explorer.exe", event.udm("ParentImage"))
        self.assertEqual("explorer.exe", event.udm("ParentCommandLine"))

    def test_network_fields(self):
        """Test Sigma network field mappings"""
        event_data = {
            "p_log_type": "SentinelOne.DeepVisibility",
            "dst_ip_address": "1.2.3.4",
            "dst_port_number": 443,
            "src_ip_address": "10.0.0.5",
            "src_port_number": 54321,
            "event_network_protocolName": "TCP",
            "url_address": "example.com",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("1.2.3.4", event.udm("DestinationIp"))
        self.assertEqual(443, event.udm("DestinationPort"))
        self.assertEqual("10.0.0.5", event.udm("SourceIp"))
        self.assertEqual(54321, event.udm("SourcePort"))
        self.assertEqual("TCP", event.udm("Protocol"))
        self.assertEqual("example.com", event.udm("DestinationHostname"))

    def test_dns_fields(self):
        """Test Sigma DNS field mappings"""
        event_data = {
            "p_log_type": "SentinelOne.DeepVisibility",
            "event_dns_request": "malicious.com",
            "event_dns_response": "A",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("malicious.com", event.udm("query"))
        self.assertEqual("malicious.com", event.udm("QueryName"))
        self.assertEqual("A", event.udm("answer"))
        self.assertEqual("A", event.udm("record_type"))

    def test_file_fields(self):
        """Test Sigma file field mappings"""
        event_data = {
            "p_log_type": "SentinelOne.DeepVisibility",
            "tgt_file_path": "C:\\Users\\user\\Downloads\\malware.exe",
            "tgt_file_oldPath": "C:\\Temp\\old_file.exe",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("C:\\Users\\user\\Downloads\\malware.exe", event.udm("TargetFilename"))
        self.assertEqual("C:\\Temp\\old_file.exe", event.udm("SourceFilename"))

    def test_registry_fields(self):
        """Test Sigma registry field mappings"""
        event_data = {
            "p_log_type": "SentinelOne.DeepVisibility",
            "registry_keyPath": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "malware.exe",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            event.udm("TargetObject"),
        )
        self.assertEqual("malware.exe", event.udm("Details"))

    def test_destination_hostname_fallback(self):
        """Test DestinationHostname falls back to event_dns_request"""
        event_data_with_url = {
            "p_log_type": "SentinelOne.DeepVisibility",
            "url_address": "example.com",
            "event_dns_request": "fallback.com",
        }
        event1 = PantherEvent(event_data_with_url, self.data_model)
        self.assertEqual("example.com", event1.udm("DestinationHostname"))

        event_data_without_url = {
            "p_log_type": "SentinelOne.DeepVisibility",
            "event_dns_request": "fallback.com",
        }
        event2 = PantherEvent(event_data_without_url, self.data_model)
        self.assertEqual("fallback.com", event2.udm("DestinationHostname"))


class TestCrowdStrikeFDRDataModel(unittest.TestCase):
    data_model = log_type_to_data_model.get("Crowdstrike.FDREvent")

    def test_existing_udm_mappings(self):
        """Test existing UDM field mappings still work"""
        event_data = {
            "p_log_type": "Crowdstrike.FDREvent",
            "event": {
                "UserName": "DOMAIN\\user",
                "CommandLine": "powershell.exe -encodedcommand ABC123",
                "RemoteAddressIP4": "1.2.3.4",
                "RemotePort": 443,
                "DomainName": "malicious.com.",
                "ImageFileName": "C:\\Windows\\System32\\powershell.exe",
                "LocalPort": 54321,
            },
            "aip": "10.0.0.5",
            "event_platform": "Win",
        }
        event = PantherEvent(event_data, self.data_model)

        # Test existing UDM mappings
        self.assertEqual("DOMAIN\\user", event.udm("actor_user"))
        self.assertEqual("powershell.exe -encodedcommand ABC123", event.udm("cmd"))
        self.assertEqual("1.2.3.4", event.udm("destination_ip"))
        self.assertEqual(443, event.udm("destination_port"))
        self.assertEqual("malicious.com", event.udm("dns_query"))  # Trailing period stripped
        self.assertEqual("powershell.exe", event.udm("process_name"))
        self.assertEqual("10.0.0.5", event.udm("source_ip"))
        self.assertEqual(54321, event.udm("source_port"))

    def test_sigma_process_fields(self):
        """Test Sigma process creation field mappings"""
        event_data = {
            "p_log_type": "Crowdstrike.FDREvent",
            "event": {
                "ImageFileName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "UserName": "DOMAIN\\user",
                "ParentBaseFileName": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "explorer.exe",
                "ContextProcessId": 1234,
                "ParentProcessId": 5678,
                "IntegrityLevel": "High",
            },
            "event_platform": "Win",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("C:\\Windows\\System32\\cmd.exe", event.udm("Image"))
        self.assertEqual("cmd.exe /c whoami", event.udm("CommandLine"))
        self.assertEqual("DOMAIN\\user", event.udm("User"))
        self.assertEqual("C:\\Windows\\explorer.exe", event.udm("ParentImage"))
        self.assertEqual("explorer.exe", event.udm("ParentCommandLine"))
        self.assertEqual("explorer.exe", event.udm("ParentProcessName"))
        self.assertEqual(1234, event.udm("ProcessId"))
        self.assertEqual(5678, event.udm("ParentProcessId"))
        self.assertEqual("High", event.udm("IntegrityLevel"))

    def test_sigma_hash_fields(self):
        """Test Sigma hash field mappings"""
        event_data = {
            "p_log_type": "Crowdstrike.FDREvent",
            "event": {
                "SHA256HashData": "abc123def456",
                "SHA1HashData": "ghi789jkl012",
                "MD5HashData": "mno345pqr678",
            },
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("abc123def456", event.udm("sha256"))
        self.assertEqual("ghi789jkl012", event.udm("sha1"))
        self.assertEqual("mno345pqr678", event.udm("md5"))

    def test_sigma_network_fields(self):
        """Test Sigma network field mappings"""
        event_data = {
            "p_log_type": "Crowdstrike.FDREvent",
            "event": {
                "RemoteAddressIP4": "1.2.3.4",
                "RemotePort": 443,
                "LocalPort": 54321,
            },
            "aip": "10.0.0.5",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("1.2.3.4", event.udm("DestinationIp"))
        self.assertEqual(443, event.udm("DestinationPort"))
        self.assertEqual("10.0.0.5", event.udm("SourceIp"))
        self.assertEqual(54321, event.udm("SourcePort"))
        self.assertEqual("1.2.3.4", event.udm("dst_ip"))
        self.assertEqual(443, event.udm("dst_port"))
        self.assertEqual("10.0.0.5", event.udm("src_ip"))
        self.assertEqual(54321, event.udm("src_port"))

    def test_sigma_dns_fields(self):
        """Test Sigma DNS field mappings"""
        event_data = {
            "p_log_type": "Crowdstrike.FDREvent",
            "event": {
                "DomainName": "example.com.",
                "IP4Records": "1.2.3.4,5.6.7.8",
            },
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("example.com", event.udm("QueryName"))  # Trailing period stripped
        self.assertEqual("example.com", event.udm("query"))  # Trailing period stripped
        self.assertEqual("1.2.3.4,5.6.7.8", event.udm("QueryResults"))

    def test_process_name_linux_mac(self):
        """Test process name extraction for Linux and Mac platforms"""
        linux_event = {
            "p_log_type": "Crowdstrike.FDREvent",
            "event": {
                "ImageFileName": "/usr/bin/bash",
                "ParentBaseFileName": "/usr/sbin/sshd",
            },
            "event_platform": "Lin",
        }
        event1 = PantherEvent(linux_event, self.data_model)
        self.assertEqual("bash", event1.udm("process_name"))
        self.assertEqual("sshd", event1.udm("ParentProcessName"))

        mac_event = {
            "p_log_type": "Crowdstrike.FDREvent",
            "event": {
                "ImageFileName": "/usr/libexec/xpcproxy",
                "ParentBaseFileName": "/sbin/launchd",
            },
            "event_platform": "Mac",
        }
        event2 = PantherEvent(mac_event, self.data_model)
        self.assertEqual("xpcproxy", event2.udm("process_name"))
        self.assertEqual("launchd", event2.udm("ParentProcessName"))


class TestCarbonBlackEndpointDataModel(unittest.TestCase):
    data_model = log_type_to_data_model.get("CarbonBlack.EndpointEvent")

    def test_sigma_process_fields(self):
        """Test Sigma process creation field mappings"""
        event_data = {
            "p_log_type": "CarbonBlack.EndpointEvent",
            "process_path": "C:\\Windows\\System32\\powershell.exe",
            "parent_path": "C:\\Windows\\explorer.exe",
            "target_cmdline": "powershell.exe -encodedcommand ABC123",
            "process_cmdline": "explorer.exe",
            "process_username": "DOMAIN\\user",
            "process_pid": 1234,
            "parent_pid": 5678,
            "process_md5": "abc123def456",
            "process_sha256": "ghi789jkl012mno345pqr678",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("C:\\Windows\\System32\\powershell.exe", event.udm("Image"))
        self.assertEqual("C:\\Windows\\explorer.exe", event.udm("ParentImage"))
        self.assertEqual("powershell.exe -encodedcommand ABC123", event.udm("CommandLine"))
        self.assertEqual("explorer.exe", event.udm("ParentCommandLine"))
        self.assertEqual("DOMAIN\\user", event.udm("User"))
        self.assertEqual(1234, event.udm("ProcessId"))
        self.assertEqual(5678, event.udm("ParentProcessId"))
        self.assertEqual("powershell.exe", event.udm("ProcessName"))
        self.assertEqual("explorer.exe", event.udm("ParentProcessName"))

    def test_sigma_hash_fields(self):
        """Test Sigma hash field mappings"""
        event_data = {
            "p_log_type": "CarbonBlack.EndpointEvent",
            "process_md5": "abc123def456",
            "process_sha256": "ghi789jkl012mno345pqr678",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("abc123def456", event.udm("md5"))
        self.assertEqual("ghi789jkl012mno345pqr678", event.udm("sha256"))

    def test_sigma_network_fields(self):
        """Test Sigma network field mappings"""
        event_data = {
            "p_log_type": "CarbonBlack.EndpointEvent",
            "remote_ip": "1.2.3.4",
            "remote_port": 443,
            "netconn_domain": "malicious.com",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("1.2.3.4", event.udm("DestinationIp"))
        self.assertEqual(443, event.udm("DestinationPort"))
        self.assertEqual("malicious.com", event.udm("DestinationHostname"))
        self.assertEqual("1.2.3.4", event.udm("dst_ip"))
        self.assertEqual(443, event.udm("dst_port"))

    def test_sigma_file_fields(self):
        """Test Sigma file field mappings"""
        event_data = {
            "p_log_type": "CarbonBlack.EndpointEvent",
            "filemod_name": "C:\\Users\\user\\Downloads\\malware.exe",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("C:\\Users\\user\\Downloads\\malware.exe", event.udm("TargetFilename"))

    def test_standard_udm_fields(self):
        """Test standard UDM field mappings"""
        event_data = {
            "p_log_type": "CarbonBlack.EndpointEvent",
            "process_username": "DOMAIN\\administrator",
            "process_path": "C:\\Windows\\System32\\cmd.exe",
            "parent_path": "C:\\Windows\\System32\\services.exe",
            "remote_ip": "10.0.0.5",
            "remote_port": 8080,
            "target_cmdline": "cmd.exe /c whoami",
        }
        event = PantherEvent(event_data, self.data_model)

        self.assertEqual("DOMAIN\\administrator", event.udm("actor_user"))
        self.assertEqual("cmd.exe", event.udm("process_name"))
        self.assertEqual("services.exe", event.udm("parent_process_name"))
        self.assertEqual("10.0.0.5", event.udm("destination_ip"))
        self.assertEqual(8080, event.udm("destination_port"))
        self.assertEqual("cmd.exe /c whoami", event.udm("cmd"))

    def test_process_name_unix_paths(self):
        """Test process name extraction for Unix paths"""
        unix_event = {
            "p_log_type": "CarbonBlack.EndpointEvent",
            "process_path": "/usr/bin/bash",
            "parent_path": "/usr/sbin/sshd",
        }
        event = PantherEvent(unix_event, self.data_model)

        self.assertEqual("bash", event.udm("ProcessName"))
        self.assertEqual("sshd", event.udm("ParentProcessName"))
        self.assertEqual("bash", event.udm("process_name"))
        self.assertEqual("sshd", event.udm("parent_process_name"))
