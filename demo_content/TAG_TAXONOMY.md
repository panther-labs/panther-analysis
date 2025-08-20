# Demo Content Tag Taxonomy

This document defines the standardized tag taxonomy used across all demo detection rules for monthly compliance and threat model reporting.

## Overview

The tag taxonomy is designed to enable structured reporting across multiple dimensions:
- **Compliance frameworks** (SOC 2, ISO 27001, NIST CSF)
- **Threat intelligence** (MITRE ATT&CK mapping)
- **Use case categorization** (insider threats, SIEM integrity, etc.)
- **Asset classification** (identity systems, detection controls, etc.)
- **Risk assessment** (impact and likelihood ratings)

## Tag Categories

### Compliance Framework Tags

Tags that map detections to specific compliance requirements:

- `compliance.soc2` - SOC 2 Type II controls
- `compliance.change_management` - Change management processes
- `compliance.nist_csf` - NIST Cybersecurity Framework
- `compliance.iso27001` - ISO 27001 information security management

**Usage Example:**
```yaml
Tags:
  - compliance.soc2
  - compliance.change_management
```

**Reporting Query:**
```sql
SELECT COUNT(*) as soc2_alerts 
FROM panther_logs.public.alerts 
WHERE ARRAY_CONTAINS('compliance.soc2'::VARIANT, p_any_tags)
  AND p_occurs_since('30 d');
```

### MITRE ATT&CK Mapping

Structured tags following MITRE ATT&CK framework nomenclature:

- `mitre.ta0003.persistence` - Persistence tactics
- `mitre.ta0004.privilege_escalation` - Privilege escalation tactics
- `mitre.ta0005.defense_evasion` - Defense evasion tactics
- `mitre.ta0006.credential_access` - Credential access tactics
- `mitre.ta0040.impact` - Impact tactics
- `mitre.t1110.brute_force` - Brute force techniques
- `mitre.t1562.impair_defenses` - Impair defenses techniques

**Usage Example:**
```yaml
Tags:
  - mitre.ta0005.defense_evasion
  - mitre.t1562.impair_defenses
```

**Reporting Query:**
```sql
SELECT 
  CASE 
    WHEN ARRAY_CONTAINS('mitre.ta0003.persistence'::VARIANT, p_any_tags) THEN 'Persistence'
    WHEN ARRAY_CONTAINS('mitre.ta0005.defense_evasion'::VARIANT, p_any_tags) THEN 'Defense Evasion'
    WHEN ARRAY_CONTAINS('mitre.ta0006.credential_access'::VARIANT, p_any_tags) THEN 'Credential Access'
    ELSE 'Other'
  END as attack_tactic,
  COUNT(*) as alert_count
FROM panther_logs.public.alerts 
WHERE p_occurs_since('30 d')
GROUP BY attack_tactic;
```

### Use Case Categories

High-level security use case classifications:

- `usecase.privileged_access_monitoring` - Monitoring privileged account activity
- `usecase.siem_integrity` - SIEM system integrity and availability
- `usecase.insider_threat_detection` - Detecting malicious insider activity
- `usecase.authentication_monitoring` - Authentication and access control
- `usecase.configuration_management` - System configuration changes

**Usage Example:**
```yaml
Tags:
  - usecase.privileged_access_monitoring
  - usecase.insider_threat_detection
```

**Reporting Query:**
```sql
SELECT 
  REGEXP_EXTRACT(tag_value, 'usecase\.(.+)', 1) as use_case,
  COUNT(*) as alert_count
FROM panther_logs.public.alerts,
     LATERAL FLATTEN(input => p_any_tags) f
WHERE f.value LIKE 'usecase.%'
  AND p_occurs_since('30 d')
GROUP BY use_case
ORDER BY alert_count DESC;
```

### Asset Classification

Technology assets and systems being monitored:

- `asset.identity_management` - Identity and access management systems
- `asset.detection_controls` - Security detection and monitoring systems
- `asset.logging_infrastructure` - Log collection and processing systems
- `asset.api_credentials` - API keys and service credentials

**Usage Example:**
```yaml
Tags:
  - asset.identity_management
  - asset.detection_controls
```

### Risk Assessment Tags

Risk and impact classification:

- `risk.high` - High risk events requiring immediate attention
- `risk.medium` - Medium risk events requiring investigation
- `impact.availability` - Events affecting system availability

**Usage Example:**
```yaml
Tags:
  - risk.high
  - impact.availability
```

**Reporting Query:**
```sql
SELECT 
  severity,
  CASE 
    WHEN ARRAY_CONTAINS('risk.high'::VARIANT, p_any_tags) THEN 'High Risk'
    WHEN ARRAY_CONTAINS('risk.medium'::VARIANT, p_any_tags) THEN 'Medium Risk'
    ELSE 'Standard Risk'
  END as risk_level,
  COUNT(*) as alert_count
FROM panther_logs.public.alerts 
WHERE p_occurs_since('30 d')
GROUP BY severity, risk_level
ORDER BY alert_count DESC;
```

### Threat Intelligence

Threat actor and attack vector classification:

- `threat.insider` - Insider threat scenarios
- `threat.external` - External threat actors
- `threat.automated` - Automated/bot-driven attacks

**Usage Example:**
```yaml
Tags:
  - threat.insider
  - threat.external
```

## Monthly Reporting Examples

### Executive Dashboard Query
```sql
-- Monthly security metrics summary
SELECT 
  DATE_TRUNC('month', p_event_time) as report_month,
  COUNT(*) as total_alerts,
  COUNT_IF(ARRAY_CONTAINS('risk.high'::VARIANT, p_any_tags)) as high_risk_alerts,
  COUNT_IF(ARRAY_CONTAINS('threat.insider'::VARIANT, p_any_tags)) as insider_threats,
  COUNT_IF(ARRAY_CONTAINS('compliance.soc2'::VARIANT, p_any_tags)) as soc2_related
FROM panther_logs.public.alerts 
WHERE p_occurs_since('3 months')
GROUP BY report_month
ORDER BY report_month DESC;
```

### Compliance Coverage Report
```sql
-- SOC 2 control coverage
SELECT 
  rule_id,
  COUNT(*) as alert_count,
  ARRAY_TO_STRING(ARRAY_AGG(DISTINCT 
    CASE WHEN f.value LIKE 'compliance.%' THEN f.value END
  ), ', ') as compliance_frameworks
FROM panther_logs.public.alerts,
     LATERAL FLATTEN(input => p_any_tags) f
WHERE ARRAY_CONTAINS('compliance.soc2'::VARIANT, p_any_tags)
  AND p_occurs_since('30 d')
GROUP BY rule_id
ORDER BY alert_count DESC;
```

### MITRE ATT&CK Coverage Analysis
```sql
-- Attack technique frequency
SELECT 
  REGEXP_EXTRACT(f.value, 'mitre\.(t\d+)\..*', 1) as technique_id,
  REGEXP_EXTRACT(f.value, 'mitre\.t\d+\.(.+)', 1) as technique_name,
  COUNT(*) as detection_count
FROM panther_logs.public.alerts,
     LATERAL FLATTEN(input => p_any_tags) f
WHERE f.value LIKE 'mitre.t%'
  AND p_occurs_since('30 d')
GROUP BY technique_id, technique_name
ORDER BY detection_count DESC;
```

### Insider Threat Analysis
```sql
-- High-risk insider threat events
SELECT 
  p_event_time,
  rule_id,
  title,
  severity,
  actor_name,
  source_ip
FROM panther_logs.public.alerts 
WHERE ARRAY_CONTAINS('threat.insider'::VARIANT, p_any_tags)
  AND ARRAY_CONTAINS('risk.high'::VARIANT, p_any_tags)
  AND p_occurs_since('7 d')
ORDER BY p_event_time DESC;
```

## Implementation Guidelines

### Tag Naming Conventions

1. **Lowercase with dots**: `category.subcategory.specific`
2. **No spaces**: Use underscores for multi-word concepts
3. **Consistent prefixes**: Each category has a standard prefix
4. **Hierarchical structure**: General to specific categorization

### Required Tags

Every demo detection rule must include:
- `demo` - Identifies rule as demonstration content
- At least one compliance tag
- At least one use case tag
- A risk assessment tag

### Optional Tags

Additional context tags as appropriate:
- MITRE ATT&CK mappings
- Asset classifications
- Threat intelligence indicators
- Impact assessments

## Maintenance

### Regular Review

- Monthly review of tag usage and effectiveness
- Quarterly alignment with compliance requirements
- Annual taxonomy updates based on threat landscape changes

### Quality Assurance

- Automated validation of tag syntax and structure
- Manual review of tag relevance and accuracy
- Consistency checks across similar detection rules

---

*This taxonomy is designed to support comprehensive security reporting, compliance validation, and threat landscape analysis through structured tagging of security detection rules.*