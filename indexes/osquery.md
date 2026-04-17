## Osquery

- [A backdoored version of XZ or liblzma is vulnerable to CVE-2024-3094](../rules/osquery_rules/osquery_linux_mac_vulnerable_xz_liblzma.yml)
  - Detects vulnerable versions of XZ and liblzma on Linux and MacOS using Osquery logs. Versions 5.6.0 and 5.6.1 of xz and liblzma are most likely vulnerable to backdoor exploit. Vuln management pack must be enabled: https://github.com/osquery/osquery/blob/master/packs/vuln-management.conf
- [A Login from Outside the Corporate Office](../rules/osquery_rules/osquery_linux_logins_non_office.yml)
  - A system has been logged into from a non approved IP space.
- [AWS command executed on the command line](../rules/osquery_rules/osquery_linux_aws_commands.yml)
  - An AWS command was executed on a Linux instance
- [MacOS ALF is misconfigured](../rules/osquery_rules/osquery_mac_application_firewall.yml)
  - The application level firewall blocks unwanted network connections made to your computer from other computers on your network.
- [MacOS Keyboard Events](../rules/osquery_rules/osquery_mac_osx_attacks_keyboard_events.yml)
  - A Key Logger has potentially been detected on a macOS system
- [macOS Malware Detected with osquery](../rules/osquery_rules/osquery_mac_osx_attacks.yml)
  - Malware has potentially been detected on a macOS system
- [Osquery Agent Outdated](../rules/osquery_rules/osquery_outdated.yml)
  - Keep track of osquery versions, current is 5.10.2.
- [OSQuery Detected SSH Listener](../rules/osquery_rules/osquery_ssh_listener.yml)
  - Check if SSH is listening in a non-production environment. This could be an indicator of persistent access within an environment.
- [OSQuery Detected Unwanted Chrome Extensions](../rules/osquery_rules/osquery_mac_unwanted_chrome_extensions.yml)
  - Monitor for chrome extensions that could lead to a credential compromise.
- [OSQuery Reports Application Firewall Disabled](../rules/osquery_rules/osquery_mac_enable_auto_update.yml)
  - Verifies that MacOS has automatic software updates enabled.
- [OSSEC Rootkit Detected via Osquery](../rules/osquery_rules/osquery_ossec.yml)
  - Checks if any results are returned for the Osquery OSSEC Rootkit pack.
- [Suspicious cron detected](../rules/osquery_rules/osquery_suspicious_cron.yml)
  - A suspicious cron has been added
- [Unsupported macOS version](../rules/osquery_rules/osquery_outdated_macos.yml)
  - Check that all laptops on the corporate environment are on a version of MacOS supported by IT.


