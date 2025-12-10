# Unified Sigma to Panther EDR Rules Guide

This guide shows you how to convert Sigma rules into Panther rules that work across multiple EDR platforms using standardized `event.udm()` field mappings.

## Overview

The Panther Analysis repository includes Sigma field mappings for three major EDR platforms:
- **SentinelOne Deep Visibility** (`SentinelOne.DeepVisibility`)
- **CrowdStrike FDR** (`Crowdstrike.FDREvent`)
- **Carbon Black Endpoint** (`CarbonBlack.EndpointEvent`)

By using `event.udm("sigma_field_name")`, you can write detection rules once and have them work across all three EDR platforms.

## Quick Start: Automated Conversion

**The fastest way** to convert Sigma rules is using the **unified Sigma EDR pipeline** in [pySigma-backend-panther](https://github.com/panther-labs/pySigma-backend-panther):

```bash
# Convert a single Sigma rule
sigma convert -t panther -p unified_sigma_edrs_panther -f udm rule.yml

# Convert multiple rules to a directory
sigma convert -t panther -p unified_sigma_edrs_panther -f udm -O output_dir=rules/ sigma_rules/
```

This automatically:
- ✅ Converts Sigma fields to `event.udm()` calls
- ✅ Adds all three EDR log types
- ✅ Handles OS and event category filtering
- ✅ Generates both Python and YAML files

**For details**, see the [pipeline documentation](https://github.com/panther-labs/pySigma-backend-panther/blob/main/UNIFIED_EDR_PIPELINE.md).

The rest of this guide explains how the conversion works and how to write rules manually.

## Core Concept

**Instead of writing vendor-specific code:**
```python
# SentinelOne
image = event.get("tgt_process_image_path")

# CrowdStrike
image = deep_get(event, "event", "ImageFileName")

# Carbon Black
image = event.get("process_path")
```

**Write unified code using Sigma field names:**
```python
# Works for all three EDRs!
image = event.udm("Image")
```

## Supported Sigma Fields Across All EDRs

The following Sigma fields are mapped and available across all three EDR platforms:

### Process Creation Fields

| Sigma Field | Description | Available in All EDRs |
|-------------|-------------|:---------------------:|
| `Image` | Full path to process executable | ✅ |
| `CommandLine` | Process command line | ✅ |
| `ParentImage` | Full path to parent process executable | ✅ |
| `ParentCommandLine` | Parent process command line | ✅ |
| `User` | Username running the process | ✅ |
| `ProcessId` | Process ID (PID) | ✅ |
| `ParentProcessId` | Parent process ID | ✅ |
| `ProcessName` | Process executable name only | ✅ |
| `ParentProcessName` | Parent process executable name only | ✅ |
| `IntegrityLevel` | Process integrity level | ✅ |

### Hash Fields

| Sigma Field | Description | Available in All EDRs |
|-------------|-------------|:---------------------:|
| `md5` | MD5 hash of process executable | ✅ |
| `sha1` | SHA1 hash of process executable | ✅ |
| `sha256` | SHA256 hash of process executable | ✅ |

### Network Fields

| Sigma Field | Description | Available in All EDRs |
|-------------|-------------|:---------------------:|
| `DestinationIp` / `dst_ip` | Destination IP address | ✅ |
| `DestinationPort` / `dst_port` | Destination port | ✅ |
| `DestinationHostname` | Destination domain/hostname | ✅ |
| `SourceIp` / `src_ip` | Source IP address | ✅ |
| `SourcePort` / `src_port` | Source port | ✅ |

### DNS Fields

| Sigma Field | Description | Available in All EDRs |
|-------------|-------------|:---------------------:|
| `QueryName` / `query` | DNS query domain name | ✅ |

### File Operation Fields

| Sigma Field | Description | Available in All EDRs |
|-------------|-------------|:---------------------:|
| `TargetFilename` | Target file path | ✅ |

## Step-by-Step Sigma to Panther Conversion

### Step 1: Identify the Sigma Rule Pattern

Example Sigma rule detecting encoded PowerShell:

```yaml
title: Encoded PowerShell Command
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
```

### Step 2: Create a Panther Rule Template

Create both a `.py` and `.yml` file:

**File: `encoded_powershell.py`**

```python
def rule(event):
    """
    Detects encoded PowerShell commands across all EDRs
    """
    # Use Sigma field names via event.udm()
    image = event.udm("Image")
    cmdline = event.udm("CommandLine")

    # Check if PowerShell is being executed
    if not image or "powershell.exe" not in image.lower():
        return False

    # Check for encoded command flags
    if not cmdline:
        return False

    cmdline_lower = cmdline.lower()
    return any(flag in cmdline_lower for flag in ["-enc", "-encodedcommand"])


def title(event):
    """Generate dynamic alert title"""
    image = event.udm("ProcessName") or "Unknown Process"
    user = event.udm("User") or "Unknown User"
    return f"Encoded PowerShell Detected: {image} by {user}"


def severity(event):
    """Dynamic severity based on user context"""
    user = event.udm("User") or ""
    # Higher severity for privileged accounts
    if any(keyword in user.lower() for keyword in ["admin", "system", "service"]):
        return "CRITICAL"
    return "HIGH"
```

**File: `encoded_powershell.yml`**

```yaml
AnalysisType: rule
RuleID: "EDR.EncodedPowerShell"
DisplayName: "Encoded PowerShell Command Execution"
Enabled: true
Filename: encoded_powershell.py
LogTypes:
  - SentinelOne.DeepVisibility
  - Crowdstrike.FDREvent
  - CarbonBlack.EndpointEvent
Severity: High
Description: >
  Detects execution of PowerShell with encoded command parameters,
  which is commonly used to obfuscate malicious commands.
Reference: https://attack.mitre.org/techniques/T1059/001/
Tags:
  - Attack.Execution
  - Attack.T1059.001
Tests:
  - Name: "PowerShell with -encodedcommand"
    ExpectedResult: true
    Log:
      p_log_type: "SentinelOne.DeepVisibility"
      tgt_process_image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      tgt_process_cmdline: "powershell.exe -encodedcommand ABC123DEF456"
      tgt_process_user: "DOMAIN\\user"
  - Name: "Normal PowerShell script"
    ExpectedResult: false
    Log:
      p_log_type: "Crowdstrike.FDREvent"
      event:
        ImageFileName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        CommandLine: "powershell.exe -File normal_script.ps1"
        UserName: "DOMAIN\\user"
  - Name: "Non-PowerShell process"
    ExpectedResult: false
    Log:
      p_log_type: "CarbonBlack.EndpointEvent"
      process_path: "C:\\Windows\\System32\\cmd.exe"
      target_cmdline: "cmd.exe /c whoami"
      process_username: "DOMAIN\\user"
```

### Step 3: Advanced Pattern - Network Connections

Example Sigma rule for suspicious network connections:

```yaml
title: Suspicious Network Connection
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort:
      - 4444
      - 5555
      - 8080
  condition: selection
```

**Panther Implementation:**

```python
SUSPICIOUS_PORTS = {4444, 5555, 8080}

def rule(event):
    """
    Detects network connections to commonly abused ports
    """
    dest_port = event.udm("DestinationPort")

    if not dest_port:
        return False

    return int(dest_port) in SUSPICIOUS_PORTS


def alert_context(event):
    """Provide additional context for investigation"""
    return {
        "process_name": event.udm("ProcessName"),
        "process_path": event.udm("Image"),
        "command_line": event.udm("CommandLine"),
        "destination_ip": event.udm("DestinationIp"),
        "destination_port": event.udm("DestinationPort"),
        "destination_hostname": event.udm("DestinationHostname"),
        "source_ip": event.udm("SourceIp"),
        "user": event.udm("User"),
        "process_id": event.udm("ProcessId"),
        "parent_process": event.udm("ParentImage"),
    }
```

## Common Patterns and Best Practices

### Pattern 1: Process Execution Detection

```python
def rule(event):
    """Detect suspicious process execution"""
    image = event.udm("Image")
    cmdline = event.udm("CommandLine")
    parent = event.udm("ParentImage")

    # Check process
    if not image:
        return False

    # Suspicious process name
    suspicious_processes = ["mimikatz.exe", "procdump.exe", "psexec.exe"]
    if any(proc in image.lower() for proc in suspicious_processes):
        return True

    # Suspicious parent-child relationship
    if parent and "cmd.exe" in image.lower() and "explorer.exe" in parent.lower():
        return True

    return False
```

### Pattern 2: Hash-Based Detection

```python
KNOWN_MALICIOUS_HASHES = {
    "abc123def456...",  # Known malware SHA256
    "789ghi012jkl...",
}

def rule(event):
    """Detect execution of known malicious files"""
    sha256 = event.udm("sha256")

    if not sha256:
        return False

    return sha256.lower() in KNOWN_MALICIOUS_HASHES
```

### Pattern 3: DNS Query Detection

```python
MALICIOUS_DOMAINS = [
    "malicious.com",
    "bad-site.net",
    "attacker-c2.org",
]

def rule(event):
    """Detect DNS queries to known malicious domains"""
    query = event.udm("QueryName") or event.udm("query")

    if not query:
        return False

    query_lower = query.lower()
    return any(domain in query_lower for domain in MALICIOUS_DOMAINS)
```

### Pattern 4: File Operation Detection

```python
SENSITIVE_PATHS = [
    "\\windows\\system32\\config\\sam",
    "\\windows\\system32\\config\\system",
    "\\users\\*\\ntuser.dat",
]

def rule(event):
    """Detect file access to sensitive locations"""
    target_file = event.udm("TargetFilename")

    if not target_file:
        return False

    target_lower = target_file.lower()
    return any(path.lower() in target_lower for path in SENSITIVE_PATHS)
```

### Pattern 5: Multi-Condition Detection with Context

```python
def rule(event):
    """
    Complex detection with multiple conditions
    """
    # Process information
    image = event.udm("Image")
    cmdline = event.udm("CommandLine")
    parent = event.udm("ParentImage")
    user = event.udm("User")

    # Network information
    dest_ip = event.udm("DestinationIp")
    dest_port = event.udm("DestinationPort")
    dest_host = event.udm("DestinationHostname")

    # Hash information
    sha256 = event.udm("sha256")

    # Condition 1: Suspicious process
    suspicious_process = image and "powershell.exe" in image.lower()

    # Condition 2: Encoded command
    encoded_command = cmdline and "-encodedcommand" in cmdline.lower()

    # Condition 3: Network connection
    external_connection = dest_ip and not dest_ip.startswith("10.")

    # Condition 4: Non-admin user
    non_admin = user and "admin" not in user.lower()

    # Alert if suspicious process with encoded command connecting externally
    return suspicious_process and encoded_command and external_connection
```

## Testing Your Rules

Always include test cases for all three EDR platforms:

```yaml
Tests:
  # Test with SentinelOne event
  - Name: "SentinelOne - Malicious PowerShell"
    ExpectedResult: true
    Log:
      p_log_type: "SentinelOne.DeepVisibility"
      tgt_process_image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      tgt_process_cmdline: "powershell.exe -encodedcommand ABC123"
      tgt_process_user: "DOMAIN\\user"
      dst_ip_address: "1.2.3.4"
      dst_port_number: 443

  # Test with CrowdStrike event
  - Name: "CrowdStrike - Malicious PowerShell"
    ExpectedResult: true
    Log:
      p_log_type: "Crowdstrike.FDREvent"
      event:
        ImageFileName: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        CommandLine: "powershell.exe -encodedcommand ABC123"
        UserName: "DOMAIN\\user"
        RemoteAddressIP4: "1.2.3.4"
        RemotePort: 443
      aip: "10.0.0.5"
      event_platform: "Win"

  # Test with Carbon Black event
  - Name: "Carbon Black - Malicious PowerShell"
    ExpectedResult: true
    Log:
      p_log_type: "CarbonBlack.EndpointEvent"
      process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      target_cmdline: "powershell.exe -encodedcommand ABC123"
      process_username: "DOMAIN\\user"
      remote_ip: "1.2.3.4"
      remote_port: 443

  # Negative test case
  - Name: "Benign PowerShell Activity"
    ExpectedResult: false
    Log:
      p_log_type: "SentinelOne.DeepVisibility"
      tgt_process_image_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      tgt_process_cmdline: "powershell.exe -File legitimate_script.ps1"
      tgt_process_user: "DOMAIN\\user"
```

## Complete Example: Lateral Movement Detection

Here's a complete example detecting lateral movement via PsExec:

**File: `psexec_lateral_movement.py`**

```python
def rule(event):
    """
    Detects PsExec-based lateral movement across all EDR platforms
    """
    # Get process information using Sigma field names
    image = event.udm("Image")
    cmdline = event.udm("CommandLine")
    parent = event.udm("ParentImage")
    user = event.udm("User")

    # Get network information
    dest_ip = event.udm("DestinationIp")
    dest_port = event.udm("DestinationPort")

    # Check for PsExec execution
    if not image or not cmdline:
        return False

    image_lower = image.lower()
    cmdline_lower = cmdline.lower()

    # Detect PsExec by name or characteristics
    psexec_indicators = [
        "psexec" in image_lower,
        "psexesvc" in image_lower,
        "\\accepteula" in cmdline_lower,
        "-accepteula" in cmdline_lower,
    ]

    if not any(psexec_indicators):
        return False

    # Additional suspicious indicators
    network_connection = dest_ip and dest_port == 445  # SMB
    suspicious_parent = parent and "cmd.exe" in parent.lower()

    # Alert on PsExec with network connection or suspicious parent
    return network_connection or suspicious_parent


def title(event):
    """Generate descriptive alert title"""
    image = event.udm("ProcessName") or event.udm("Image") or "Unknown"
    dest_ip = event.udm("DestinationIp") or "unknown destination"
    user = event.udm("User") or "unknown user"

    return f"PsExec Lateral Movement: {image} by {user} to {dest_ip}"


def severity(event):
    """Dynamic severity based on context"""
    user = event.udm("User") or ""
    dest_ip = event.udm("DestinationIp") or ""

    # Critical if privileged account
    if any(keyword in user.lower() for keyword in ["admin", "service", "system"]):
        return "CRITICAL"

    # High if external connection
    if dest_ip and not any(dest_ip.startswith(prefix) for prefix in ["10.", "172.16.", "192.168."]):
        return "HIGH"

    return "MEDIUM"


def alert_context(event):
    """Provide comprehensive context for investigation"""
    return {
        # Process context
        "process": event.udm("Image"),
        "process_name": event.udm("ProcessName"),
        "command_line": event.udm("CommandLine"),
        "process_id": event.udm("ProcessId"),
        "user": event.udm("User"),

        # Parent process context
        "parent_process": event.udm("ParentImage"),
        "parent_process_name": event.udm("ParentProcessName"),
        "parent_command_line": event.udm("ParentCommandLine"),
        "parent_process_id": event.udm("ParentProcessId"),

        # Network context
        "destination_ip": event.udm("DestinationIp"),
        "destination_port": event.udm("DestinationPort"),
        "destination_hostname": event.udm("DestinationHostname"),
        "source_ip": event.udm("SourceIp"),

        # Hash context
        "md5": event.udm("md5"),
        "sha1": event.udm("sha1"),
        "sha256": event.udm("sha256"),
    }
```

**File: `psexec_lateral_movement.yml`**

```yaml
AnalysisType: rule
RuleID: "EDR.LateralMovement.PsExec"
DisplayName: "PsExec Lateral Movement Detection"
Enabled: true
Filename: psexec_lateral_movement.py
LogTypes:
  - SentinelOne.DeepVisibility
  - Crowdstrike.FDREvent
  - CarbonBlack.EndpointEvent
Severity: High
Description: >
  Detects potential lateral movement via PsExec across multiple EDR platforms.
  PsExec is commonly used by attackers for lateral movement after initial compromise.
Reference: https://attack.mitre.org/techniques/T1021/002/
Runbook: >
  1. Verify if the PsExec usage is authorized
  2. Check the user account for compromise
  3. Investigate the destination system
  4. Review recent authentication logs
  5. Check for other lateral movement indicators
Tags:
  - Attack.LateralMovement
  - Attack.T1021.002
  - PsExec
DedupPeriodMinutes: 60
Threshold: 1
```

## Field Mapping Quick Reference

### Process Fields
```python
event.udm("Image")              # Full process path
event.udm("CommandLine")        # Process command line
event.udm("ParentImage")        # Full parent path
event.udm("ParentCommandLine")  # Parent command line
event.udm("User")               # Username
event.udm("ProcessId")          # Process ID
event.udm("ParentProcessId")    # Parent PID
event.udm("ProcessName")        # Process name only
event.udm("ParentProcessName")  # Parent name only
event.udm("IntegrityLevel")     # Integrity level
```

### Hash Fields
```python
event.udm("md5")      # MD5 hash
event.udm("sha1")     # SHA1 hash
event.udm("sha256")   # SHA256 hash
```

### Network Fields
```python
event.udm("DestinationIp")       # Destination IP
event.udm("DestinationPort")     # Destination port
event.udm("DestinationHostname") # Destination hostname
event.udm("SourceIp")            # Source IP
event.udm("SourcePort")          # Source port
```

### DNS Fields
```python
event.udm("QueryName")  # DNS query
event.udm("query")      # DNS query (alias)
```

### File Fields
```python
event.udm("TargetFilename")  # Target file path
```

## Benefits of This Approach

1. **Write Once, Run Everywhere**: Single rule works across all three EDR platforms
2. **Easier Maintenance**: Update one rule instead of three
3. **Consistent Detection**: Same logic across all platforms
4. **Sigma Compatibility**: Easy migration from Sigma rules
5. **Future-Proof**: Easy to add new EDR platforms

## Tips and Best Practices

### 1. Always Check for None
```python
# Good
image = event.udm("Image")
if image and "suspicious.exe" in image.lower():
    return True

# Bad - may throw AttributeError
if "suspicious.exe" in event.udm("Image").lower():
    return True
```

### 2. Use Lowercase for Comparisons
```python
# Good - case insensitive
image = event.udm("Image")
if image and "powershell.exe" in image.lower():
    return True

# Bad - case sensitive, may miss variants
if "PowerShell.exe" in event.udm("Image"):
    return True
```

### 3. Provide Rich Context
```python
def alert_context(event):
    """Always return comprehensive context"""
    return {
        "process": event.udm("Image"),
        "command_line": event.udm("CommandLine"),
        "user": event.udm("User"),
        "parent": event.udm("ParentImage"),
        "network": event.udm("DestinationIp"),
        "hash": event.udm("sha256"),
    }
```

### 4. Use Dynamic Severity
```python
def severity(event):
    """Adjust severity based on context"""
    user = event.udm("User") or ""
    if "admin" in user.lower() or "system" in user.lower():
        return "CRITICAL"
    return "HIGH"
```

### 5. Test Across All Platforms
Always include test cases for all three EDR platforms in your YAML file.

## Related Documentation

- [Sigma Field Mapping Reference](./SIGMA_FIELD_MAPPING_REFERENCE.md) - Complete field mapping tables for all three EDRs
- [README - Sigma EDR](./README_SIGMA_EDR.md) - Overview and quick start
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) - Official Sigma rule format
- [pySigma Backend for Panther](https://github.com/panther-labs/pySigma-backend-panther) - Sigma to Panther conversion tool

## Support

For questions or issues with the EDR data models:
1. Check the [Sigma Field Mapping Reference](./SIGMA_FIELD_MAPPING_REFERENCE.md) for field mappings
2. Review test cases in `data_models/data_models_test.py`
3. Consult the [Panther documentation](https://docs.panther.com/)
