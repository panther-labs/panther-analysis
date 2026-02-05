# Sigma Field Mapping Reference - EDR Comparison

Quick reference table showing how Sigma fields map to native fields across SentinelOne, CrowdStrike FDR, and Carbon Black Endpoint.

## Normalized Metadata Fields

These special fields normalize event type and OS detection across all EDRs. They are automatically used by the unified Sigma EDR pipeline.

### Event Category Field (`_event_category`)

Maps native event type fields to standard Sigma categories:

| Sigma Category | SentinelOne Field/Value | CrowdStrike Field/Value | Carbon Black Field/Value |
|----------------|-------------------------|-------------------------|--------------------------|
| `process_creation` | `EventType="Process Creation"` | `event_simpleName` in `["ProcessRollup2", "SyntheticProcessRollup2"]` | `type="endpoint.event.procstart"` |
| `file_event` | `EventType="File Modification"`, `"File Rename"`, `"File Delete"` | `event_simpleName="FileOpenInfo"` | `type="endpoint.event.filemod"` |
| `image_load` | `EventType="ModuleLoad"` | `event_simpleName="ModuleLoad"` | _Not available_ |
| `pipe_creation` | `EventType="Pipe Creation"` | `event_simpleName="NamedPipeEvent"` | _Not available_ |
| `registry_event` | `EventType` in `["Registry Key Create", "Registry Key Delete", "Registry Value Create", "Registry Value Modified", "Registry Value Delete"]` | `event_simpleName` in `["RegKeySecurityChanged", "RegKeyCreated", "RegKeyDeleted"]` | `type="endpoint.event.regmod"` |
| `dns_query` | `ObjectType="DNS"` | `event_simpleName="DnsRequest"` | `type="endpoint.event.netconn"` AND `netconn_protocol="PROTO_DNS"` |
| `network_connection` | `EventType="IP Connect"` | `event_simpleName` in `["NetworkConnectIP4", "NetworkConnectIP6"]` | `type="endpoint.event.netconn"` |

**Usage in rules:**
```python
# Check for process creation events across all EDRs
if event.udm("_event_category") == "process_creation":
    # Process creation logic
```

### OS Field (`_os`)

Maps native OS fields to standard values:

| OS Value | SentinelOne Field/Value | CrowdStrike Field/Value | Carbon Black Field/Value |
|----------|-------------------------|-------------------------|--------------------------|
| `windows` | `EndpointOS="windows"` | `event_platform="Win"` | `device_os="WINDOWS"` |
| `linux` | `EndpointOS="linux"` | `event_platform="Linux"` | `device_os="LINUX"` |
| `macos` | `EndpointOS="osx"` | `event_platform="Mac"` | `device_os="MAC"` |

**Usage in rules:**
```python
# Check for Windows events across all EDRs
if event.udm("_os") == "windows":
    # Windows-specific logic
```

## Process Creation Fields

| Sigma Field | SentinelOne Deep Visibility | CrowdStrike FDR | Carbon Black Endpoint |
|-------------|---------------------------|-----------------|---------------------|
| `Image` | `tgt_process_image_path` | `event.ImageFileName` | `process_path` |
| `CommandLine` | `tgt_process_cmdline` | `event.CommandLine` | `target_cmdline` |
| `User` | `tgt_process_user` | `event.UserName` | `process_username` |
| `ProcessId` | `tgt_process_pid` | `event.ContextProcessId` | `process_pid` |
| `ParentImage` | `src_process_image_path` | `event.ParentBaseFileName` | `parent_path` |
| `ParentCommandLine` | `src_process_cmdline` | `event.ParentCommandLine` | `process_cmdline` |
| `ParentProcessId` | `src_process_pid` | `event.ParentProcessId` | `parent_pid` |
| `ProcessName` | Extracted from `tgt_process_image_path` | Extracted from `event.ImageFileName` | Extracted from `process_path` |
| `ParentProcessName` | Extracted from `src_process_image_path` | Extracted from `event.ParentBaseFileName` | Extracted from `parent_path` |
| `IntegrityLevel` | `tgt_process_integrityLevel` | `event.IntegrityLevel` | _Not available_ |

## Hash Fields

| Sigma Field | SentinelOne Deep Visibility | CrowdStrike FDR | Carbon Black Endpoint |
|-------------|---------------------------|-----------------|---------------------|
| `md5` | `tgt_process_image_md5` | `event.MD5HashData` | `process_md5` |
| `sha1` | `tgt_process_image_sha1` | `event.SHA1HashData` | `process_sha1` |
| `sha256` | `tgt_process_image_sha256` | `event.SHA256HashData` | `process_sha256` |

## Network Fields

| Sigma Field | SentinelOne Deep Visibility | CrowdStrike FDR | Carbon Black Endpoint |
|-------------|---------------------------|-----------------|---------------------|
| `DestinationIp` | `dst_ip_address` | `event.RemoteAddressIP4` | `remote_ip` |
| `DestinationPort` | `dst_port_number` | `event.RemotePort` | `remote_port` |
| `DestinationHostname` | `url_address` (fallback: `event_dns_request`) | _Not available_ | `netconn_domain` |
| `SourceIp` | `src_ip_address` | `aip` | `local_ip` |
| `SourcePort` | `src_port_number` | `event.LocalPort` | `local_port` |
| `Protocol` | `event_network_protocolName` | _Not available_ | _Not available_ |

## DNS Fields

| Sigma Field | SentinelOne Deep Visibility | CrowdStrike FDR | Carbon Black Endpoint |
|-------------|---------------------------|-----------------|---------------------|
| `QueryName` / `query` | `event_dns_request` | `event.DomainName` (trailing period stripped) | `dns_query` |
| `answer` / `record_type` | `event_dns_response` | _Not available_ | _Not available_ |
| `QueryResults` | _Not available_ | `event.IP4Records` | _Not available_ |

## File Operation Fields

| Sigma Field | SentinelOne Deep Visibility | CrowdStrike FDR | Carbon Black Endpoint |
|-------------|---------------------------|-----------------|---------------------|
| `TargetFilename` | `tgt_file_path` | `event.TargetFileName` | `filemod_name` |
| `SourceFilename` | `tgt_file_oldPath` | _Not available_ | _Not available_ |

## SentinelOne-Specific Fields

These fields are unique to SentinelOne and not available in other EDRs:

| Sigma Field | SentinelOne Field | Description |
|-------------|------------------|-------------|
| `Description` | `tgt_process_displayName` | Process display name |
| `Product` | `tgt_process_displayName` | Process product name |
| `Company` | `tgt_process_publisher` | Process publisher |
| `CurrentDirectory` | `tgt_process_image_path` | Current working directory |
| `TerminalSessionId` | `tgt_process_sessionId` | Terminal session ID |
| `ImageLoaded` | `module_path` | Loaded module path |
| `module_sha1` | `module_sha1` | Module SHA1 hash |
| `module_md5` | `module_md5` | Module MD5 hash |
| `PipeName` | `namedPipe_name` | Named pipe name |
| `TargetObject` | `registry_keyPath` | Registry key path |
| `Details` | `registry_value` | Registry value |

## Standard UDM Field Mappings

All three data models also support standard Panther UDM field names:

| UDM Field | Sigma Equivalent | Description |
|-----------|-----------------|-------------|
| `actor_user` | `User` | Username running the process |
| `cmd` | `CommandLine` | Process command line |
| `process_name` | `ProcessName` | Process executable name |
| `parent_process_name` | `ParentProcessName` | Parent process executable name |
| `destination_ip` | `DestinationIp` | Destination IP address |
| `destination_port` | `DestinationPort` | Destination port |
| `source_ip` | `SourceIp` | Source IP address |
| `source_port` | `SourcePort` | Source port |
| `dns_query` | `QueryName` | DNS query domain |
| `dst_ip` | `DestinationIp` | Destination IP (alias) |
| `dst_port` | `DestinationPort` | Destination port (alias) |
| `src_ip` | `SourceIp` | Source IP (alias) |
| `src_port` | `SourcePort` | Source port (alias) |

## Usage Examples

### Using Sigma Field Names
```python
# Works across all three EDRs
image = event.udm("Image")
cmdline = event.udm("CommandLine")
user = event.udm("User")
dest_ip = event.udm("DestinationIp")
```

### Using UDM Field Names
```python
# Also works across all three EDRs
user = event.udm("actor_user")
cmd = event.udm("cmd")
dest_ip = event.udm("destination_ip")
proc_name = event.udm("process_name")
```

### Accessing Native Fields Directly

If you need to access platform-specific fields:

**SentinelOne:**
```python
image = event.get("tgt_process_image_path")
cmdline = event.get("tgt_process_cmdline")
```

**CrowdStrike FDR:**
```python
from panther_base_helpers import deep_get
image = deep_get(event, "event", "ImageFileName")
cmdline = deep_get(event, "event", "CommandLine")
```

**Carbon Black:**
```python
image = event.get("process_path")
cmdline = event.get("target_cmdline")
```

## Field Availability Legend

- ✅ **Available**: Field is mapped and available
- 🔧 **Computed**: Field is computed from other fields (e.g., process name extracted from path)
- ⚠️ **Limited**: Field may not always be populated
- ❌ **Not Available**: Field is not available in this EDR

## Notes

1. **Process Name Extraction**: `ProcessName` and `ParentProcessName` are automatically extracted from full paths across all EDRs, handling both Windows (`\`) and Unix (`/`) path separators.

2. **DNS Query Normalization**: CrowdStrike FDR automatically strips trailing periods from DNS queries (e.g., `example.com.` becomes `example.com`).

3. **DestinationHostname**:
   - SentinelOne: Falls back to `event_dns_request` if `url_address` is not available
   - CrowdStrike: Not directly available as a hostname field
   - Carbon Black: Available as `netconn_domain`

4. **Case Sensitivity**: Always use exact field name casing when calling `event.udm()`. Field names are case-sensitive.

5. **Field Availability**: Some fields may not be populated for all event types. Always check for `None` before using field values.

## Quick Reference Command

To check which fields are available for a specific log type:

```python
# In your rule or in testing
def rule(event):
    # Get the log type
    log_type = event.get("p_log_type")

    # Try to access a field
    image = event.udm("Image")

    if not image:
        # Field not available or not populated
        return False

    return True
```

## Related Documentation

- [Unified Sigma EDR Guide](./UNIFIED_SIGMA_EDR_GUIDE.md) - Complete guide for writing cross-platform detection rules
- [README - Sigma EDR](./README_SIGMA_EDR.md) - Overview and quick start
