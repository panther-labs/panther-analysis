## OneLogin

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [ako_testing_indexes](../rules/standard_rules/ako_testing_indexes.yml)
  - Testing indexes generating workflow for AKo
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


