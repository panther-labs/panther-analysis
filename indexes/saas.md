## Box

- [Box Access Granted](../rules/box_rules/box_access_granted.yml)
  - A user granted access to their box account to Box technical support from account settings.
- [Box Content Workflow Policy Violation](../rules/box_rules/box_policy_violation.yml)
  - A user violated the content workflow policy.
- [Box event triggered by unknown or external user](../rules/box_rules/box_event_triggered_externally.yml)
  - An external user has triggered a box enterprise event.
- [Box item shared externally](../rules/box_rules/box_item_shared_externally.yml)
  - A user has shared an item and it is accessible to anyone with the share link (internal or external to the company). This rule requires that the boxsdk[jwt] be installed in the environment.
- [Box Large Number of Downloads](../rules/box_rules/box_user_downloads.yml)
  - A user has exceeded the threshold for number of downloads within a single time frame.
- [Box Large Number of Permission Changes](../rules/box_rules/box_user_permission_updates.yml)
  - A user has exceeded the threshold for number of folder permission changes within a single time frame.
- [Box New Login](../rules/box_rules/box_new_login.yml)
  - A user logged in from a new device.
- [Box Shield Detected Anomalous Download Activity](../rules/box_rules/box_anomalous_download.yml)
  - A user's download activity has altered significantly.
- [Box Shield Suspicious Alert Triggered](../rules/box_rules/box_suspicious_login_or_session.yml)
  - A user login event or session event was tagged as medium to high severity by Box Shield.
- [Box Untrusted Device Login](../rules/box_rules/box_untrusted_device.yml)
  - A user attempted to login from an untrusted device.
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Malicious Content Detected](../rules/box_rules/box_malicious_content.yml)
  - Box has detect malicious content, such as a virus.
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


## Dropbox

- [Dropbox Admin sign-in-as Session](../rules/dropbox_rules/dropbox_admin_sign_in_as_session.yml)
  - Alerts when an admin starts a sign-in-as session.
- [Dropbox Document/Folder Ownership Transfer](../rules/dropbox_rules/dropbox_ownership_transfer.yml)
  - Dropbox ownership of a document or folder has been transferred.
- [Dropbox External Share](../rules/dropbox_rules/dropbox_external_share.yml)
  - Dropbox item shared externally
- [Dropbox Linked Team Application Added](../rules/dropbox_rules/dropbox_linked_team_application_added.yml)
  - An application was linked to your Dropbox Account
- [Dropbox Many Deletes](../queries/dropbox_queries/Dropbox_Many_Deletes_Query.yml)
  - Dropbox Many Deletes
- [Dropbox Many Downloads](../queries/dropbox_queries/Dropbox_Many_Downloads.yml)
  - Detects when a dropbox user downloads many documents.
- [Dropbox User Disabled 2FA](../rules/dropbox_rules/dropbox_user_disabled_2fa.yml)
  - Dropbox user has disabled 2fa login


## Google Workspace

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [External GSuite File Share](../rules/gsuite_reports_rules/gsuite_drive_external_share.yml)
  - An employee shared a sensitive file externally with another organization
- [Google Accessed a GSuite Resource](../rules/gsuite_activityevent_rules/gsuite_google_access.yml)
  - Google accessed one of your GSuite resources directly, most likely in response to a support incident.
- [Google Drive High Download Count](../queries/gsuite_queries/gsuite_drive_many_docs_downloaded.yml)
  - Scheduled rule for the High Google Drive Download Count query which looks for incidents of more than 10 (tunable) downloads by a user in the past day.
- [Google Workspace Admin Custom Role](../rules/gsuite_activityevent_rules/google_workspace_admin_custom_role.yml)
  - A Google Workspace administrator created a new custom administrator role.
- [Google Workspace Advanced Protection Program](../rules/gsuite_activityevent_rules/google_workspace_advanced_protection_program.yml)
  - Your organization's Google Workspace Advanced Protection Program settings were modified.
- [Google Workspace Apps Marketplace Allowlist](../rules/gsuite_activityevent_rules/google_workspace_apps_marketplace_allowlist.yml)
  - Google Workspace Marketplace application allowlist settings were modified.
- [Google Workspace Apps Marketplace New Domain Application](../rules/gsuite_activityevent_rules/google_workspace_apps_marketplace_new_domain_application.yml)
  - A Google Workspace User configured a new domain application from the Google Workspace Apps Marketplace.
- [Google Workspace Apps New Mobile App Installed](../rules/gsuite_activityevent_rules/google_workspace_apps_new_mobile_app_installed.yml)
  - A new mobile application was added to your organization's mobile apps whitelist in Google Workspace Apps.
- [GSuite Calendar Has Been Made Public](../rules/gsuite_activityevent_rules/gsuite_calendar_made_public.yml)
  - A User or Admin Has Modified A Calendar To Be Public
- [GSuite Device Suspicious Activity](../rules/gsuite_activityevent_rules/gsuite_mobile_device_suspicious_activity.yml)
  - GSuite reported a suspicious activity on a user's device.
- [GSuite Document External Ownership Transfer](../rules/gsuite_activityevent_rules/gsuite_doc_ownership_transfer.yml)
  - A GSuite document's ownership was transferred to an external party.
- [GSuite Drive Many Documents Deleted](../queries/gsuite_queries/gsuite_drive_many_docs_deleted.yml)
  - Scheduled rule for the GSuite Drive Many Documents Deleted query. Looks for users who have deleted more than 10 (tunable) documents the past day.
- [GSuite External Drive Document](../rules/gsuite_reports_rules/gsuite_drive_visibility_change.yml)
  - A Google drive resource became externally accessible.
- [GSuite Government Backed Attack](../rules/gsuite_activityevent_rules/gsuite_gov_attack.yml)
  - GSuite reported that it detected a government backed attack against your account.
- [GSuite Login Type](../rules/gsuite_activityevent_rules/gsuite_login_type.yml)
  - A login of a non-approved type was detected for this user.
- [Gsuite Mail forwarded to external domain](../rules/gsuite_activityevent_rules/gsuite_external_forwarding.yml)
  - A user has configured mail forwarding to an external domain
- [GSuite Many Docs Deleted Query](../queries/gsuite_queries/GSuite_Many_Docs_Deleted_Query.yml)
  - Query to search for a user deleting many documents.
- [GSuite Many Docs Downloaded Query](../queries/gsuite_queries/GSuite_Many_Docs_Downloaded_Query.yml)
  - Query to search high document download counts by users.
- [GSuite Overly Visible Drive Document](../rules/gsuite_reports_rules/gsuite_drive_overly_visible.yml)
  - A Google drive resource that is overly visible has been modified.
- [GSuite Passthrough Rule Triggered](../rules/gsuite_activityevent_rules/gsuite_passthrough_rule.yml)
  - A GSuite rule was triggered.
- [GSuite User Advanced Protection Change](../rules/gsuite_activityevent_rules/gsuite_advanced_protection.yml)
  - A user disabled advanced protection for themselves.
- [GSuite User Banned from Group](../rules/gsuite_activityevent_rules/gsuite_group_banned_user.yml)
  - A GSuite user was banned from an enterprise group by moderator action.
- [GSuite User Device Compromised](../rules/gsuite_activityevent_rules/gsuite_mobile_device_compromise.yml)
  - GSuite reported a user's device has been compromised.
- [GSuite User Device Unlock Failures](../rules/gsuite_activityevent_rules/gsuite_mobile_device_screen_unlock_fail.yml)
  - Someone failed to unlock a user's device multiple times in quick succession.
- [GSuite User Password Leaked](../rules/gsuite_activityevent_rules/gsuite_leaked_password.yml)
  - GSuite reported a user's password has been compromised, so they disabled the account.
- [GSuite User Suspended](../rules/gsuite_activityevent_rules/gsuite_user_suspended.yml)
  - A GSuite user was suspended, the account may have been compromised by a spam network.
- [GSuite User Two Step Verification Change](../rules/gsuite_activityevent_rules/gsuite_two_step_verification.yml)
  - A user disabled two step verification for themselves.
- [GSuite Workspace Calendar External Sharing Setting Change](../rules/gsuite_activityevent_rules/gsuite_workspace_calendar_external_sharing.yml)
  - A Workspace Admin Changed The Sharing Settings for Primary Calendars
- [GSuite Workspace Data Export Has Been Created](../rules/gsuite_activityevent_rules/gsuite_workspace_data_export_created.yml)
  - A Workspace Admin Has Created a Data Export
- [GSuite Workspace Gmail Default Routing Rule Modified](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_default_routing_rule.yml)
  - A Workspace Admin Has Modified A Default Routing Rule In Gmail
- [GSuite Workspace Gmail Pre-Delivery Message Scanning Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_enhanced_predelivery_scanning.yml)
  - A Workspace Admin Has Disabled Pre-Delivery Scanning For Gmail.
- [GSuite Workspace Gmail Security Sandbox Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_security_sandbox_disabled.yml)
  - A Workspace Admin Has Disabled The Security Sandbox
- [GSuite Workspace Password Reuse Has Been Enabled](../rules/gsuite_activityevent_rules/gsuite_workspace_password_reuse_enabled.yml)
  - A Workspace Admin Has Enabled Password Reuse
- [GSuite Workspace Strong Password Enforcement Has Been Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_password_enforce_strong_disabled.yml)
  - A Workspace Admin Has Disabled The Enforcement Of Strong Passwords
- [GSuite Workspace Trusted Domain Allowlist Modified](../rules/gsuite_activityevent_rules/gsuite_workspace_trusted_domains_allowlist.yml)
  - A Workspace Admin Has Modified The Trusted Domains List
- [Suspicious GSuite Login](../rules/gsuite_activityevent_rules/gsuite_suspicious_logins.yml)
  - GSuite reported a suspicious login for this user.


## Okta

- [AWS Console Sign-In NOT PRECEDED BY Okta Redirect](../correlation_rules/aws_console_sign-in_without_okta.yml)
  - A user has logged into the AWS console without authenticating via Okta.  This rule requires AWS SSO via Okta, both log sources configured, and Actor Profiles enabled.
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
  - A user has subsequent logins from two geographic locations that are very far apart
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
  - Detects when Multi-Factor Authentication (MFA) is disabled
- [Okta Admin Access Granted](../queries/okta_queries/okta_admin_access_granted.yml)
  - Audit instances of admin access granted in your okta tenant
- [Okta Admin Role Assigned](../rules/okta_rules/okta_admin_role_assigned.yml)
  - A user has been granted administrative privileges in Okta
- [Okta AiTM Phishing Attempt Blocked by FastPass](../rules/okta_rules/okta_phishing_attempt_blocked_by_fastpass.yml)
  - Okta FastPass detected a user targeted by attackers wielding real-time (AiTM) proxies.
- [Okta API Key Created](../rules/okta_rules/okta_api_key_created.yml)
  - A user created an API Key in Okta
- [Okta API Key Revoked](../rules/okta_rules/okta_api_key_revoked.yml)
  - A user has revoked an API Key in Okta
- [Okta App Refresh Access Token Reuse](../rules/okta_rules/okta_app_refresh_access_token_reuse.yml)
  - When a client wants to renew an access token, it sends the refresh token with the access token request to the /token Okta endpoint.Okta validates the incoming refresh token, issues a new set of tokens and invalidates the refresh token that was passed with the initial request.This detection alerts when a previously used refresh token is used again with the token request
- [Okta App Unauthorized Access Attempt](../rules/okta_rules/okta_app_unauthorized_access_attempt.yml)
  - Detects when a user is denied access to an Okta application
- [Okta Cleartext Passwords Extracted via SCIM Application](../rules/okta_rules/okta_password_extraction_via_scim.yml)
  - An application admin has extracted cleartext user passwords via SCIM app. Malcious actors can extract plaintext passwords by creating a SCIM application under their control and configuring it to sync passwords from Okta.
- [Okta Group Admin Role Assigned](../rules/okta_rules/okta_group_admin_role_assigned.yml)
  - Detect when an admin role is assigned to a group
- [Okta HAR File IOCs](../queries/okta_queries/okta_harfile_iocs.yml)
  - https://sec.okta.com/harfiles
- [Okta Identity Provider Created or Modified](../rules/okta_rules/okta_idp_create_modify.yml)
  - A new 3rd party Identity Provider has been created or modified. Attackers have been observed configuring a second Identity Provider to act as an "impersonation app" to access applications within the compromised Org on behalf of other users. This second Identity Provider, also controlled by the attacker, would act as a “source” IdP in an inbound federation relationship (sometimes called “Org2Org”) with the target.
- [Okta Identity Provider Sign-in](../rules/okta_rules/okta_idp_signin.yml)
  - A user has signed in using a 3rd party Identity Provider. Attackers have been observed configuring a second Identity Provider to act as an "impersonation app" to access applications within the compromised Org on behalf of other users. This second Identity Provider, also controlled by the attacker, would act as a “source” IdP in an inbound federation relationship (sometimes called “Org2Org”) with the target. From this “source” IdP, the threat actor manipulated the username parameter for targeted users in the second “source” Identity Provider to match a real user in the compromised “target” Identity Provider. This provided the ability to Single sign-on (SSO) into applications in the target IdP as the targeted user. Do not use this rule if your organization uses legitimate 3rd-party Identity Providers.
- [Okta Investigate MFA and Password resets](../queries/okta_queries/okta_mfa_password_reset_audit.yml)
  - Investigate Password and MFA resets for the last 7 days
- [Okta Investigate Session ID Activity](../queries/okta_queries/okta_session_id_audit.yml)
  - Search for activity related to a specific SessionID in Okta panther_logs.okta_systemlog
- [Okta Investigate User Activity](../queries/okta_queries/okta_activity_audit.yml)
  - Audit user activity across your environment. Customize to filter on specific users, time ranges, etc
- [Okta Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device.yml)
  - Detects Okta Logins from IP addresses not found in CrowdStrike's AIP list. May indicate unmanaged device being used, or faulty CrowdStrike Sensor.
- [Okta Login From CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/okta_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device_FDREvent.yml)
  - Okta Logins from an IP Address not found in CrowdStrike's AIP List (crowdstrike_fdrevent table)
- [Okta MFA Globally Disabled](../rules/okta_rules/okta_admin_disabled_mfa.yml)
  - An admin user has disabled the MFA requirement for your Okta account
- [Okta New Behaviors Acessing Admin Console](../rules/okta_rules/okta_new_behavior_accessing_admin_console.yml)
  - New Behaviors Observed while Accessing Okta Admin Console. A user attempted to access the Okta Admin Console from a new device with a new IP.
- [Okta Org2Org application created of modified](../rules/okta_rules/okta_org2org_creation_modification.yml)
  - An Okta Org2Org application has been created or modified. Okta's Org2Org applications instances are used to push and match users from one Okta organization to another. A malicious actor can add an Org2Org application instance and create a user in the source organization (controlled by the attacker) with the same identifier as a Super Administrator in the target organization.
- [Okta Password Accessed](../rules/okta_rules/okta_password_accessed.yml)
  - User accessed another user's application password
- [Okta Potentially Stolen Session](../rules/okta_rules/okta_potentially_stolen_session.yml)
  - This rule looks for the same session being used from two devices, indicating a compromised session token.
- [Okta Rate Limits](../rules/okta_rules/okta_rate_limits.yml)
  - Potential DoS/Bruteforce attack or hitting limits (system degradation)
- [Okta Sign-In from VPN Anonymizer](../rules/okta_rules/okta_anonymizing_vpn_login.yml)
  - A user is attempting to sign-in to Okta from a known VPN anonymizer.  The threat actor would access the compromised account using anonymizing proxy services.
- [Okta Support Access](../queries/okta_queries/okta_support_access.yml)
  - Show instances that Okta support was granted to your account
- [Okta Support Access Granted](../rules/okta_rules/okta_account_support_access.yml)
  - An admin user has granted access to Okta Support to your account
- [Okta Support Reset Credential](../rules/okta_rules/okta_support_reset.yml)
  - A Password or MFA factor was reset by Okta Support
- [Okta ThreatInsight Security Threat Detected](../rules/okta_rules/okta_threatinsight_security_threat_detected.yml)
  - Okta ThreatInsight identified request from potentially malicious IP address
- [Okta User Account Locked](../rules/okta_rules/okta_user_account_locked.yml)
  - An Okta user has locked their account.
- [Okta User MFA Factor Suspend](../rules/okta_rules/okta_user_mfa_factor_suspend.yml)
  - Suspend factor or authenticator enrollment method for user.
- [Okta User MFA Own Reset](../rules/okta_rules/okta_user_mfa_reset.yml)
  - User has reset one of their own MFA factors
- [Okta User MFA Reset All](../rules/okta_rules/okta_user_mfa_reset_all.yml)
  - All MFA factors have been reset for a user.
- [Okta User Reported Suspicious Activity](../rules/okta_rules/okta_user_reported_suspicious_activity.yml)
  - Suspicious Activity Reporting provides an end user with the option to report unrecognized activity from an account activity email notification.This detection alerts when a user marks the raised activity as suspicious.
- [Okta Username Above 52 Characters Security Advisory](../queries/okta_queries/okta_52_char_username_threat_hunt.yml)
  - On October 30, 2024, a vulnerability was internally identified in generating the cache key for AD/LDAP DelAuth. The Bcrypt algorithm was used to generate the cache key where we hash a combined string of userId + username + password. Under a specific set of conditions, listed below, this could allow users to authenticate by providing the username with the stored cache key of a previous successful authentication. Customers meeting the pre-conditions should investigate their Okta System Log for unexpected authentications from usernames greater than 52 characters between the period of July 23rd, 2024 to October 30th, 2024. https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


## OneLogin

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
  - A new account was created
- [OneLogin Active Login Activity](../rules/onelogin_rules/onelogin_active_login_activity.yml)
  - Multiple user accounts logged in from the same ip address.
- [OneLogin Authentication Factor Removed](../rules/onelogin_rules/onelogin_remove_authentication_factor.yml)
  - A user removed an authentication factor or otp device.
- [OneLogin Failed High Risk Login](../rules/onelogin_rules/onelogin_high_risk_failed_login.yml)
  - A OneLogin attempt with a high risk factor (>50) resulted in a failed authentication.
- [OneLogin High Risk Failed Login FOLLOWED BY Successful Login](../correlation_rules/onelogin_successful_login_after_high_risk_failed_login.yml)
  - A OneLogin user successfully logged in after a failed high-risk login attempt.
- [OneLogin Multiple Accounts Deleted](../rules/onelogin_rules/onelogin_threshold_accounts_deleted.yml)
  - Possible Denial of Service detected. Threshold for user account deletions exceeded.
- [OneLogin Multiple Accounts Modified](../rules/onelogin_rules/onelogin_threshold_accounts_modified.yml)
  - Possible Denial of Service detected. Threshold for user account password changes exceeded.
- [OneLogin Password Access](../rules/onelogin_rules/onelogin_password_accessed.yml)
  - User accessed another user's application password
- [OneLogin Unauthorized Access](../rules/onelogin_rules/onelogin_unauthorized_access.yml)
  - A OneLogin user was denied access to an app more times than the configured threshold.
- [OneLogin User Assumed Another User](../rules/onelogin_rules/onelogin_user_assumed.yml)
  - User assumed another user account
- [OneLogin User Locked](../rules/onelogin_rules/onelogin_user_account_locked.yml)
  - User locked or suspended from their account.
- [OneLogin User Password Changed](../rules/onelogin_rules/onelogin_password_changed.yml)
  - A user password was updated.
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


## Salesforce

- [Salesforce Admin Login As User](../rules/salesforce_rules/salesforce_admin_login_as_user.yml)
  - Salesforce detection that alerts when an admin logs in as another user.


## Slack

- [Slack Anomaly Detected](../rules/slack_rules/slack_passthrough_anomaly.yml)
  - Passthrough for anomalies detected by Slack
- [Slack App Access Expanded](../rules/slack_rules/slack_app_access_expanded.yml)
  - Detects when a Slack App has had its permission scopes expanded
- [Slack App Added](../rules/slack_rules/slack_app_added.yml)
  - Detects when a Slack App has been added to a workspace
- [Slack App Removed](../rules/slack_rules/slack_app_removed.yml)
  - Detects when a Slack App has been removed
- [Slack Denial of Service](../rules/slack_rules/slack_application_dos.yml)
  - Detects when slack admin invalidates user session(s). If it happens more than once in a 24 hour period it can lead to DoS
- [Slack DLP Modified](../rules/slack_rules/slack_dlp_modified.yml)
  - Detects when a Data Loss Prevention (DLP) rule has been deactivated or a violation has been deleted
- [Slack EKM Config Changed](../rules/slack_rules/slack_ekm_config_changed.yml)
  - Detects when the logging settings for a workspace's EKM configuration has changed
- [Slack EKM Slackbot Unenrolled](../rules/slack_rules/slack_ekm_slackbot_unenrolled.yml)
  - Detects when a workspace is longer enrolled in EKM
- [Slack EKM Unenrolled](../rules/slack_rules/slack_ekm_unenrolled.yml)
  - Detects when a workspace is no longer enrolled or managed by EKM
- [Slack IDP Configuration Changed](../rules/slack_rules/slack_idp_configuration_change.yml)
  - Detects changes to the identity provider (IdP) configuration for Slack organizations.
- [Slack Information Barrier Modified](../rules/slack_rules/slack_information_barrier_modified.yml)
  - Detects when a Slack information barrier is deleted/updated
- [Slack Intune MDM Disabled](../rules/slack_rules/slack_intune_mdm_disabled.yml)
  - Detects the disabling of Microsoft Intune Enterprise MDM within Slack
- [Slack Legal Hold Policy Modified](../rules/slack_rules/slack_legal_hold_policy_modified.yml)
  - Detects changes to configured legal hold policies
- [Slack MFA Settings Changed](../rules/slack_rules/slack_mfa_settings_changed.yml)
  - Detects changes to Multi-Factor Authentication requirements
- [Slack Organization Created](../rules/slack_rules/slack_org_created.yml)
  - Detects when a Slack organization is created
- [Slack Organization Deleted](../rules/slack_rules/slack_org_deleted.yml)
  - Detects when a Slack organization is deleted
- [Slack Potentially Malicious File Shared](../rules/slack_rules/slack_potentially_malicious_file_shared.yml)
  - Detects when a potentially malicious file is shared within Slack
- [Slack Private Channel Made Public](../rules/slack_rules/slack_private_channel_made_public.yml)
  - Detects when a channel that was previously private is made public
- [Slack Service Owner Transferred](../rules/slack_rules/slack_service_owner_transferred.yml)
  - Detects transferring of service owner on request from primary owner
- [Slack SSO Settings Changed](../rules/slack_rules/slack_sso_settings_changed.yml)
  - Detects changes to Single Sign On (SSO) restrictions
- [Slack User Privilege Escalation](../rules/slack_rules/slack_user_privilege_escalation.yml)
  - Detects when a Slack user gains escalated privileges
- [Slack User Privileges Changed to User](../rules/slack_rules/slack_privilege_changed_to_user.yml)
  - Detects when a Slack account is changed to User from an elevated role.


## Teleport

- [A long-lived cert was created](../rules/gravitational_teleport_rules/teleport_long_lived_certs.yml)
  - An unusually long-lived Teleport certificate was created
- [A SAML Connector was created or modified](../rules/gravitational_teleport_rules/teleport_saml_created.yml)
  - A SAML connector was created or modified
- [A Teleport Lock was created](../rules/gravitational_teleport_rules/teleport_lock_created.yml)
  - A Teleport Lock was created
- [A Teleport Role was modified or created](../rules/gravitational_teleport_rules/teleport_role_created.yml)
  - A Teleport Role was modified or created
- [A user authenticated with SAML, but from an unknown company domain](../rules/gravitational_teleport_rules/teleport_saml_login_not_company_domain.yml)
  - A user authenticated with SAML, but from an unknown company domain
- [A User from the company domain(s) Logged in without SAML](../rules/gravitational_teleport_rules/teleport_company_domain_login_without_saml.yml)
  - A User from the company domain(s) Logged in without SAML
- [Teleport Create User Accounts](../rules/gravitational_teleport_rules/teleport_create_user_accounts.yml)
  - A user has been manually created, modified, or deleted
- [Teleport Network Scan Initiated](../rules/gravitational_teleport_rules/teleport_network_scanning.yml)
  - A user has invoked a network scan that could potentially indicate enumeration of the network.
- [Teleport Scheduled Jobs](../rules/gravitational_teleport_rules/teleport_scheduled_jobs.yml)
  - A user has manually edited the Linux crontab
- [Teleport SSH Auth Errors](../rules/gravitational_teleport_rules/teleport_auth_errors.yml)
  - A high volume of SSH errors could indicate a brute-force attack
- [Teleport Suspicious Commands Executed](../rules/gravitational_teleport_rules/teleport_suspicious_commands.yml)
  - A user has invoked a suspicious command that could lead to a host compromise
- [User Logged in as root](../rules/gravitational_teleport_rules/teleport_root_login.yml)
  - A User logged in as root
- [User Logged in wihout MFA](../rules/gravitational_teleport_rules/teleport_local_user_login_without_mfa.yml)
  - A local User logged in without MFA


## Zendesk

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Enabled Zendesk Support to Assume Users](../rules/zendesk_rules/zendesk_user_assumption.yml)
  - User enabled or disabled zendesk support user assumption.
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
  - Detects when Multi-Factor Authentication (MFA) is disabled
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks
- [Zendesk Account Owner Changed](../rules/zendesk_rules/zendesk_new_owner.yml)
  - Only one admin user can be the account owner. Ensure the change in ownership is expected.
- [Zendesk API Token Created](../rules/zendesk_rules/zendesk_new_api_token.yml)
  - A user created a new API token to be used with Zendesk.
- [Zendesk Credit Card Redaction Off](../rules/zendesk_rules/zendesk_sensitive_data_redaction.yml)
  - A user updated account setting that disabled credit card redaction.
- [Zendesk Mobile App Access Modified](../rules/zendesk_rules/zendesk_mobile_app_access.yml)
  - A user updated account setting that enabled or disabled mobile app access.
- [Zendesk User Role Changed](../rules/zendesk_rules/zendesk_user_role.yml)
  - A user's Zendesk role was changed
- [Zendesk User Suspension Status Changed](../rules/zendesk_rules/zendesk_user_suspension.yml)
  - A user's Zendesk suspension status was changed.


## Zoom

- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
  - A new account was created
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks
- [Zoom All Meetings Secured With One Option Disabled](../rules/zoom_operation_rules/zoom_all_meetings_secured_with_one_option_disabled.yml)
  - A Zoom User turned off your organization's requirement that all meetings are secured with one security option.
- [Zoom Automatic Sign Out Disabled](../rules/zoom_operation_rules/zoom_automatic_sign_out_disabled.yml)
  - A Zoom User turned off your organization's setting to automatically sign users out after a specified period of time.
- [Zoom Meeting Passcode Disabled](../rules/zoom_operation_rules/zoom_operation_passcode_disabled.yml)
  - Meeting passcode requirement has been disabled from usergroup
- [Zoom New Meeting Passcode Required Disabled](../rules/zoom_operation_rules/zoom_new_meeting_passcode_required_disabled.yml)
  - A Zoom User turned off your organization's setting to require passcodes for new meetings.
- [Zoom Sign In Method Modified](../rules/zoom_operation_rules/zoom_sign_in_method_modified.yml)
  - A Zoom User modified your organizations sign in method.
- [Zoom Sign In Requirements Changed](../rules/zoom_operation_rules/zoom_sign_in_requirements_changed.yml)
  - A Zoom User changed your organization's sign in requirements.
- [Zoom Two Factor Authentication Disabled](../rules/zoom_operation_rules/zoom_two_factor_authentication_disabled.yml)
  - A Zoom User disabled your organization's setting to sign in with Two-Factor Authentication.
- [Zoom User Promoted to Privileged Role](../rules/zoom_operation_rules/zoom_user_promoted_to_privileged_role.yml)
  - A Zoom user was promoted to a privileged role.


