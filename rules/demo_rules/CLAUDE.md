# Demo Rules Directory

This directory contains Panther security detection rules specifically designed for demonstration purposes. These rules showcase various security detection capabilities and provide examples for training, testing, and customer demonstrations.

## Repository Architecture

This repository is a **mirror of the upstream panther-analysis repository** with a specific workflow:

1. **Mirror Maintenance**: We maintain a local mirror of the upstream [panther-analysis](https://github.com/panther-labs/panther-analysis) repository
2. **Rule Selection**: Instead of modifying rules in-place, we copy relevant rules from the upstream directories into `rules/demo_rules/`
3. **Demo Customization**: Rules are renamed with `_demo` suffix and customized for demonstration scenarios
4. **Selective Upload**: **Only the `rules/demo_rules/` directory is uploaded to our Panther instance**, not the entire repository

This approach allows us to:

- Stay synchronized with upstream community rules and updates
- Maintain clean separation between production and demo content
- Customize rules specifically for demonstration without affecting upstream versions
- Deploy only curated demo rules to our instance

## Purpose

The demo rules serve multiple purposes:

- **Customer Demonstrations**: Showcasing Panther's detection capabilities across different security use cases
- **Training Materials**: Providing realistic examples for security analysts learning Panther
- **Testing Scenarios**: Supporting integration testing and validation workflows
- **Reference Implementation**: Demonstrating best practices for rule development

## Rule Origins

This collection combines rules from two primary sources:

### Claude AI-Generated Rules

Several rules were created using Claude AI to address specific demo scenarios and security use cases. These rules demonstrate modern AI-assisted security rule development and include:

- Customized detection logic for specific demo environments
- Enhanced alert context and runbook guidance
- Tailored severity levels and deduplication strategies

### Panther Analysis (Upstream) Rules

Many rules are copied and adapted from the official [panther-analysis](https://github.com/panther-labs/panther-analysis) repository, which contains:

- Community-contributed detection rules
- Panther Labs official detection content
- Industry-standard security monitoring patterns

**Important**: Rules are copied from upstream directories (e.g., `rules/aws_cloudtrail_rules/`, `rules/aws_guardduty_rules/`) into this demo directory, renamed with the `_demo` suffix, and customized as needed.

## Naming Convention

All files in this directory follow a strict naming convention:

- **Python files**: `*_demo.py`
- **YAML files**: `*_demo.yml`
- **YAML Filename field**: Must reference the corresponding `*_demo.py` file

This naming convention:

1. Clearly identifies demo-specific content
2. Prevents conflicts with production rules
3. Enables easy filtering and management
4. Maintains consistency across the directory

## File Structure

Each detection rule consists of two files:

- **`.py` file**: Contains the detection logic with required `rule()` function
- **`.yml` file**: Contains metadata, configuration, and unit tests

Example pair:

```bash
aws_console_login_demo.py    # Detection logic
aws_console_login_demo.yml   # Configuration and tests
```

## Usage Guidelines

### For Demonstrations

- Rules are pre-configured with realistic test data
- Alert contexts include relevant investigation guidance
- Severity levels are tuned for demo environments
- Deduplication periods are optimized for demo scenarios

### For Development Reference

- Review both AI-generated and community-sourced approaches
- Compare different implementation patterns
- Study test case structures and edge case handling
- Understand alert context and runbook best practices

### For Testing

- All rules include comprehensive unit tests
- Test cases cover positive, negative, and edge scenarios
- Mock data represents realistic log structures
- Tests validate alert context, titles, and deduplication

## Maintenance

### Automated Tools

- `scripts/fix_demo_naming.py`: Ensures all files follow naming convention
- Automated linting and testing via CI/CD pipeline
- Quality gates require 10.0/10 linting score and 100% test pass rate

### Manual Review

- Periodic review of rule effectiveness and relevance
- Updates to reflect new threat patterns and AWS services
- Alignment with upstream panther-analysis updates
- Customer feedback integration

## Quality Standards

All demo rules must meet the following criteria:

- **Linting**: Perfect 10.0/10 pylint score
- **Testing**: 100% test pass rate with comprehensive coverage
- **Documentation**: Clear descriptions, runbooks, and references
- **Naming**: Strict adherence to `*_demo` naming convention
- **Context**: Rich alert context for investigation guidance

## Integration

These rules are designed to integrate seamlessly with:

- Panther Cloud and Enterprise platforms
- Standard AWS log sources (CloudTrail, GuardDuty, VPC Flow, etc.)
- Panther's alert routing and case management systems
- Third-party SIEM and SOAR platforms via Panther's integrations

## Support

For questions or issues with demo rules:

1. Review the rule's YAML configuration and test cases
2. Check the main repository documentation in `/CLAUDE.md`
3. Consult the upstream panther-analysis repository for community rules
4. Leverage Panther's documentation and support resources

---

*This directory represents a curated collection of security detection rules designed specifically for demonstration and educational purposes. The combination of AI-generated and community-sourced content provides comprehensive coverage of modern cloud security monitoring scenarios.*
