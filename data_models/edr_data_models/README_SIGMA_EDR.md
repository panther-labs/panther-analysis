# Sigma Field Mappings for EDR Platforms

Write detection rules once using standard Sigma field names that work across multiple EDR platforms.

## Supported EDR Platforms

- ✅ **SentinelOne Deep Visibility** (`SentinelOne.DeepVisibility`)
- ✅ **CrowdStrike Falcon Data Replicator** (`Crowdstrike.FDREvent`)
- ✅ **Carbon Black Endpoint** (`CarbonBlack.EndpointEvent`)

## Quick Start

### Automated Conversion (Recommended)

Convert Sigma rules automatically with the unified pipeline:

```bash
# Install
pip install pysigma-backend-panther

# Convert
sigma convert -t panther -p unified_sigma_edrs_panther -f udm your_sigma_rule.yml
```

**See**: [Unified EDR Pipeline Documentation](https://github.com/panther-labs/pySigma-backend-panther/blob/main/UNIFIED_EDR_PIPELINE.md)

### Manual Rule Writing

Use `event.udm()` to access fields across all EDRs:

```python
def rule(event):
    """Works on all three EDR platforms"""
    image = event.udm("Image")
    cmdline = event.udm("CommandLine")

    if image and "powershell.exe" in image.lower():
        if cmdline and "-encodedcommand" in cmdline.lower():
            return True
    return False
```

### YAML Configuration

Specify all three log types:

```yaml
LogTypes:
  - SentinelOne.DeepVisibility
  - Crowdstrike.FDREvent
  - CarbonBlack.EndpointEvent
```

## Available Sigma Fields

**Process**: `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `ProcessId`, `ParentProcessId`, `ProcessName`, `ParentProcessName`, `IntegrityLevel`

**Hash**: `md5`, `sha1`, `sha256`

**Network**: `DestinationIp`, `DestinationPort`, `DestinationHostname`, `SourceIp`, `SourcePort`

**DNS**: `QueryName`, `query`

**File**: `TargetFilename`

**Metadata**: `_event_category`, `_os` (for filtering by event type and operating system)

## Documentation

| Document | Description |
|----------|-------------|
| **[UNIFIED_SIGMA_EDR_GUIDE.md](./UNIFIED_SIGMA_EDR_GUIDE.md)** | Complete guide with examples, patterns, and best practices |
| **[SIGMA_FIELD_MAPPING_REFERENCE.md](./SIGMA_FIELD_MAPPING_REFERENCE.md)** | Field mapping tables showing native field names for each EDR |

## Data Model Files

### SentinelOne Deep Visibility
- **Files**: `sentinelone_data_model.py`, `sentinelone_data_model.yml`
- **Log Type**: `SentinelOne.DeepVisibility`
- **Fields**: 50+ Sigma field mappings

### CrowdStrike Falcon Data Replicator
- **Files**: `crowdstrike_fdr_data_model.py`, `crowdstrike_fdr_data_model.yml`
- **Log Type**: `Crowdstrike.FDREvent`
- **Fields**: 30+ Sigma field mappings
- **Feature**: Automatic DNS query normalization

### Carbon Black Endpoint
- **Files**: `carbonblack_endpoint_data_model.py`, `carbonblack_endpoint_data_model.yml`
- **Log Type**: `CarbonBlack.EndpointEvent`
- **Fields**: 25+ Sigma field mappings

## Testing

```bash
# Run all data model tests
make data-models-unit-test

# Run specific platform tests
pipenv run python -m pytest data_models/data_models_test.py::TestSentinelOneDataModel -v
pipenv run python -m pytest data_models/data_models_test.py::TestCrowdStrikeFDRDataModel -v
pipenv run python -m pytest data_models/data_models_test.py::TestCarbonBlackEndpointDataModel -v
```

## Key Benefits

1. **Write Once, Run Everywhere** - Single rule works across all three EDR platforms
2. **Consistent Detection** - Same logic across all platforms ensures consistent security coverage
3. **Easier Maintenance** - Update one rule instead of maintaining three separate rules
4. **Sigma Compatibility** - Direct mapping from standard Sigma rules
5. **Future-Proof** - Easy to add support for additional EDR platforms

## Getting Started

1. Read the [Unified Sigma EDR Guide](./UNIFIED_SIGMA_EDR_GUIDE.md) for complete examples and patterns
2. Check the [Field Mapping Reference](./SIGMA_FIELD_MAPPING_REFERENCE.md) for specific field mappings
3. Write your rules using `event.udm()` for field access
4. Include test cases for all three EDR platforms
5. Deploy with all three log types configured

## Related Resources

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification) - Official Sigma rule format
- [pySigma Backend for Panther](https://github.com/panther-labs/pySigma-backend-panther) - Conversion tool
- [Panther Data Models Documentation](https://docs.panther.com/writing-detections/data-models) - Official docs
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques

## Support

For questions or issues:
1. Check the [Unified Sigma EDR Guide](./UNIFIED_SIGMA_EDR_GUIDE.md) for detailed examples
2. Review the [Field Mapping Reference](./SIGMA_FIELD_MAPPING_REFERENCE.md) for field mappings
3. Consult test cases in `data_models_test.py`
4. See [Panther documentation](https://docs.panther.com/)

---

**Version**: 1.0
**Last Updated**: 2024
**Maintainers**: Panther Labs Community
