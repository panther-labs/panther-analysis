## OnePassword

- [1Password Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/onepassword_login_from_crowdstrike_unmanaged_device.yml)
  - Detects 1Password Logins from IP addresses not found in CrowdStrike's AIP list. May indicate unmanaged device being used, or faulty CrowdStrike Sensor.
- [1Password Login From CrowdStrike Unmanaged Device Query](../queries/crowdstrike_queries/onepass_login_from_crowdstrike_unmanaged_device_query.yml)
  - Looks for OnePassword Logins from IP Addresses that aren't seen in CrowdStrike's AIP List.
- [1Password Login From CrowdStrike Unmanaged Device Query (crowdstrike_fdrevent table)](../queries/onepassword_queries/onepass_login_from_crowdstrike_unmanaged_device_FDREvent.yml)
  - Looks for OnePassword Logins from IP Addresses that aren't seen in CrowdStrike's AIP List. (crowdstrike_fdrevent table)
- [BETA - Sensitive 1Password Item Accessed](../rules/onepassword_rules/onepassword_lut_sensitive_item_access.yml)
  - Alerts when a user defined list of sensitive items in 1Password is accessed
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Configuration Required - Sensitive 1Password Item Accessed](../rules/onepassword_rules/onepassword_sensitive_item_access.yml)
  - Alerts when a user defined list of sensitive items in 1Password is accessed
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks
- [Unusual 1Password Client Detected](../rules/onepassword_rules/onepassword_unusual_client.yml)
  - Detects when unusual or undesirable 1Password clients access your 1Password account


