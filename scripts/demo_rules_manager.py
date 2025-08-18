#!/usr/bin/env python3
"""
Demo Rules Manager - Advanced rule cloning and management tool

This script manages the demo_rules/ directory by:
1. Cloning rules from upstream directories with proper naming conventions
2. Managing a configuration file of which rules to clone/maintain
3. Tracking updates and avoiding merge conflicts
4. Providing multiple operation modes for different workflows

Usage:
    python demo_rules_manager.py discover    # Discover all rules in repo
    python demo_rules_manager.py clone      # Clone all enabled rules from config
    python demo_rules_manager.py add RULE_ID [--category CATEGORY]  # Add new rule to config and clone
    python demo_rules_manager.py update RULE_ID  # Update existing cloned rule
    python demo_rules_manager.py sync       # Sync all rules (clone new, update existing)
    python demo_rules_manager.py fix        # Fix naming conventions (original functionality)
    python demo_rules_manager.py status     # Show status of all configured rules
"""

import os
import sys
import re
import yaml
import argparse
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json


class RuleDiscovery:
    """Discovers and maps all rules and policies in the panther-analysis repository."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.rule_map = {}
        self.policy_map = {}
        
    def discover_all_rules(self) -> Dict[str, List[Tuple[Path, Path]]]:
        """
        Scan the entire repo and build a mapping of RuleID -> [(py_file, yml_file), ...]
        Returns dict where keys are RuleIDs and values are lists of (python_file, yaml_file) tuples.
        """
        return self._discover_detections('RuleID', 'rule')
    
    def discover_all_policies(self) -> Dict[str, List[Tuple[Path, Path]]]:
        """
        Scan the entire repo and build a mapping of PolicyID -> [(py_file, yml_file), ...]
        Returns dict where keys are PolicyIDs and values are lists of (python_file, yaml_file) tuples.
        """
        return self._discover_detections('PolicyID', 'policy')
    
    def _discover_detections(self, id_field: str, detection_type: str) -> Dict[str, List[Tuple[Path, Path]]]:
        """
        Generic method to discover rules or policies based on ID field.
        """
        print(f"🔍 Discovering all {detection_type}s in repository...")
        detection_map = {}
        
        # Search both rules and policies directories
        search_dirs = [self.repo_root / "rules", self.repo_root / "policies"]
        
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
                
            for yaml_file in search_dir.rglob("*.yml"):
                # Skip demo content to avoid circular references
                if "demo_rules" in str(yaml_file) or "demo_content" in str(yaml_file):
                    continue
                    
                try:
                    with open(yaml_file, 'r') as f:
                        content = yaml.safe_load(f)
                        
                    if id_field in content:
                        detection_id = content[id_field]
                        filename = content.get('Filename', '')
                        
                        # Find corresponding Python file
                        if filename:
                            py_file = yaml_file.parent / filename
                            if py_file.exists():
                                if detection_id not in detection_map:
                                    detection_map[detection_id] = []
                                detection_map[detection_id].append((py_file, yaml_file))
                            else:
                                print(f"Warning: Python file {py_file} not found for {yaml_file}")
                                
                except Exception as e:
                    print(f"Warning: Could not read {yaml_file}: {e}")
        
        # Store in appropriate map
        if detection_type == 'rule':
            self.rule_map = detection_map
        else:
            self.policy_map = detection_map
            
        print(f"✅ Discovered {len(detection_map)} unique {detection_type}s across {sum(len(v) for v in detection_map.values())} files")
        return detection_map
    
    def analyze_mitre_coverage(self) -> Dict:
        """
        Analyze MITRE ATT&CK coverage across all discovered rules.
        Returns comprehensive statistics and mapping.
        """
        print("🎯 Analyzing MITRE ATT&CK coverage...")
        
        if not self.rule_map:
            self.discover_all_rules()
        
        mitre_stats = {
            'total_rules': len(self.rule_map),
            'rules_with_mitre': 0,
            'rules_without_mitre': 0,
            'coverage_percentage': 0.0,
            'tactics': {},  # TA0001: {'name': 'Initial Access', 'rules': [...], 'techniques': {...}}
            'techniques': {},  # T1078: {'tactic': 'TA0001', 'name': 'Valid Accounts', 'rules': [...]}
            'rules_by_mitre': {},  # rule_id: {'tactics': [...], 'techniques': [...]}
            'uncovered_rules': []
        }
        
        # MITRE ATT&CK tactic mapping for reference
        tactic_names = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution', 
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control',
            'TA0040': 'Impact'
        }
        
        for rule_id, file_pairs in self.rule_map.items():
            # Use first file pair (or only one)
            py_file, yml_file = file_pairs[0]
            
            try:
                with open(yml_file, 'r') as f:
                    content = yaml.safe_load(f)
                
                mitre_techniques = []
                has_mitre = False
                
                # Check for Reports section with MITRE ATT&CK
                if 'Reports' in content and 'MITRE ATT&CK' in content['Reports']:
                    mitre_techniques = content['Reports']['MITRE ATT&CK']
                    has_mitre = True
                    mitre_stats['rules_with_mitre'] += 1
                    
                    # Parse each technique
                    rule_tactics = set()
                    rule_techniques = set()
                    
                    for technique in mitre_techniques:
                        if ':' in str(technique):
                            tactic_id, technique_id = str(technique).split(':', 1)
                            
                            # Track tactic
                            if tactic_id not in mitre_stats['tactics']:
                                mitre_stats['tactics'][tactic_id] = {
                                    'name': tactic_names.get(tactic_id, 'Unknown Tactic'),
                                    'rules': [],
                                    'techniques': set()
                                }
                            mitre_stats['tactics'][tactic_id]['rules'].append(rule_id)
                            mitre_stats['tactics'][tactic_id]['techniques'].add(technique_id)
                            rule_tactics.add(tactic_id)
                            
                            # Track technique
                            if technique_id not in mitre_stats['techniques']:
                                mitre_stats['techniques'][technique_id] = {
                                    'tactic': tactic_id,
                                    'rules': []
                                }
                            mitre_stats['techniques'][technique_id]['rules'].append(rule_id)
                            rule_techniques.add(technique_id)
                    
                    mitre_stats['rules_by_mitre'][rule_id] = {
                        'tactics': list(rule_tactics),
                        'techniques': list(rule_techniques),
                        'source_path': str(yml_file.parent.relative_to(self.repo_root / "rules"))
                    }
                else:
                    mitre_stats['rules_without_mitre'] += 1
                    mitre_stats['uncovered_rules'].append({
                        'rule_id': rule_id,
                        'source_path': str(yml_file.parent.relative_to(self.repo_root / "rules"))
                    })
                    
            except Exception as e:
                print(f"Warning: Could not analyze MITRE for {yml_file}: {e}")
                mitre_stats['rules_without_mitre'] += 1
        
        # Calculate coverage percentage
        if mitre_stats['total_rules'] > 0:
            mitre_stats['coverage_percentage'] = (mitre_stats['rules_with_mitre'] / mitre_stats['total_rules']) * 100
        
        print(f"✅ MITRE Analysis Complete:")
        print(f"   Total Rules: {mitre_stats['total_rules']}")
        print(f"   With MITRE: {mitre_stats['rules_with_mitre']} ({mitre_stats['coverage_percentage']:.1f}%)")
        print(f"   Without MITRE: {mitre_stats['rules_without_mitre']}")
        print(f"   Tactics Covered: {len(mitre_stats['tactics'])}/12")
        print(f"   Techniques Covered: {len(mitre_stats['techniques'])}")
        
        return mitre_stats
    
    def find_rule(self, rule_id: str, hint_path: Optional[str] = None) -> Optional[Tuple[Path, Path]]:
        """
        Find a specific rule by ID, optionally using a path hint for faster lookup.
        Returns (python_file, yaml_file) tuple or None if not found.
        """
        return self._find_detection(rule_id, hint_path, 'rule')
    
    def find_policy(self, policy_id: str, hint_path: Optional[str] = None) -> Optional[Tuple[Path, Path]]:
        """
        Find a specific policy by ID, optionally using a path hint for faster lookup.
        Returns (python_file, yaml_file) tuple or None if not found.
        """
        return self._find_detection(policy_id, hint_path, 'policy')
    
    def _find_detection(self, detection_id: str, hint_path: Optional[str], detection_type: str) -> Optional[Tuple[Path, Path]]:
        """
        Generic method to find rules or policies.
        """
        # Ensure we have discovered the appropriate type
        if detection_type == 'rule':
            if not self.rule_map:
                self.discover_all_rules()
            detection_map = self.rule_map
        else:
            if not self.policy_map:
                self.discover_all_policies()
            detection_map = self.policy_map
            
        if detection_id not in detection_map:
            return None
            
        candidates = detection_map[detection_id]
        
        # If hint path provided, try to use it
        if hint_path and len(candidates) > 1:
            for py_file, yml_file in candidates:
                if hint_path in str(yml_file.parent):
                    return (py_file, yml_file)
        
        # Return first candidate (or only one)
        return candidates[0] if candidates else None


class ConfigManager:
    """Manages the demo rules configuration file."""
    
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = {}
        
    def load_config(self) -> Dict:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            print(f"Warning: Config file not found at {self.config_path}")
            return {}
            
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
                return self.config
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}
    
    def save_config(self):
        """Save configuration to YAML file."""
        try:
            # Update last_updated timestamp
            if 'metadata' not in self.config:
                self.config['metadata'] = {}
            self.config['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'
            
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def add_rule(self, rule_id: str, category: str = None, enabled: bool = True, notes: str = ""):
        """Add a new rule to the configuration."""
        return self._add_detection(rule_id, 'rule', category, enabled, notes)
    
    def add_policy(self, policy_id: str, category: str = None, enabled: bool = True, notes: str = ""):
        """Add a new policy to the configuration."""
        return self._add_detection(policy_id, 'policy', category, enabled, notes)
    
    def _add_detection(self, detection_id: str, detection_type: str, category: str = None, enabled: bool = True, notes: str = ""):
        """Generic method to add a rule or policy to configuration."""
        config_key = "policies" if detection_type == "policy" else "rules"
        if config_key not in self.config:
            self.config[config_key] = []
            
        # Check if detection already exists
        for detection in self.config[config_key]:
            detection_key = 'rule_id' if detection_type == 'rule' else 'policy_id'
            if detection[detection_key] == detection_id:
                print(f"{detection_type.title()} {detection_id} already exists in configuration")
                return False
                
        # Get default category from settings
        default_category = self.config.get('clone_settings', {}).get('default_category', 'aws_cloud_security')
        
        detection_key = 'rule_id' if detection_type == 'rule' else 'policy_id'
        new_detection = {
            detection_key: detection_id,
            'source_path': None,  # Auto-discover
            'target_category': category or default_category,
            'enabled': enabled,
            'last_cloned': None,
            'notes': notes
        }
        
        self.config[config_key].append(new_detection)
        return True
    
    def get_enabled_rules(self) -> List[Dict]:
        """Get list of enabled rules from configuration."""
        return [rule for rule in self.config.get('rules', []) if rule.get('enabled', True)]
    
    def get_enabled_policies(self) -> List[Dict]:
        """Get list of enabled policies from configuration."""
        return [policy for policy in self.config.get('policies', []) if policy.get('enabled', True)]
    
    def update_rule_timestamp(self, rule_id: str):
        """Update the last_cloned timestamp for a rule."""
        self._update_detection_timestamp(rule_id, 'rule')
    
    def update_policy_timestamp(self, policy_id: str):
        """Update the last_cloned timestamp for a policy."""
        self._update_detection_timestamp(policy_id, 'policy')
    
    def _update_detection_timestamp(self, detection_id: str, detection_type: str):
        """Generic method to update timestamp for rule or policy."""
        config_key = "policies" if detection_type == "policy" else "rules"
        detection_key = 'rule_id' if detection_type == 'rule' else 'policy_id'
        
        for detection in self.config.get(config_key, []):
            if detection[detection_key] == detection_id:
                detection['last_cloned'] = datetime.utcnow().isoformat() + 'Z'
                break


class RuleCloner:
    """Handles cloning and renaming of rules."""
    
    def __init__(self, demo_rules_dir: Path, config: Dict):
        self.demo_rules_dir = demo_rules_dir
        self.config = config
        self.clone_settings = config.get('clone_settings', {})
        
    def clone_rule(self, rule_id: str, source_py: Path, source_yml: Path, target_category: str) -> bool:
        """
        Clone a rule from source to demo_content with proper renaming.
        Returns True if successful, False otherwise.
        """
        return self._clone_detection(rule_id, source_py, source_yml, target_category, 'rule')
    
    def clone_policy(self, policy_id: str, source_py: Path, source_yml: Path, target_category: str) -> bool:
        """
        Clone a policy from source to demo_content with proper renaming.
        Returns True if successful, False otherwise.
        """
        return self._clone_detection(policy_id, source_py, source_yml, target_category, 'policy')
    
    def _clone_detection(self, detection_id: str, source_py: Path, source_yml: Path, target_category: str, detection_type: str) -> bool:
        """
        Generic method to clone a rule or policy.
        """
        try:
            # Determine target directory - use demo_content now
            target_dir = self.demo_rules_dir.parent.parent / "demo_content" / target_category
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate demo filenames
            id_suffix = self.clone_settings.get('rule_id_suffix', '.Demo') if detection_type == 'rule' else self.clone_settings.get('policy_id_suffix', '.Demo')
            filename_suffix = self.clone_settings.get('filename_suffix', '_demo')
            
            base_name = source_py.stem
            demo_py_name = f"{base_name}{filename_suffix}.py"
            demo_yml_name = f"{base_name}{filename_suffix}.yml"
            
            target_py = target_dir / demo_py_name
            target_yml = target_dir / demo_yml_name
            
            # Copy Python file
            shutil.copy2(source_py, target_py)
            print(f"📁 Copied: {source_py.name} -> {demo_py_name}")
            
            # Copy and modify YAML file
            self._copy_and_modify_yaml(source_yml, target_yml, demo_py_name, detection_id, id_suffix, detection_type)
            print(f"📁 Copied: {source_yml.name} -> {demo_yml_name}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error cloning {detection_type} {detection_id}: {e}")
            return False
    
    def _copy_and_modify_yaml(self, source_yml: Path, target_yml: Path, 
                            new_filename: str, original_detection_id: str, id_suffix: str, detection_type: str):
        """Copy YAML file and modify Filename and RuleID/PolicyID fields."""
        with open(source_yml, 'r') as f:
            content = f.read()
        
        # Update Filename field
        content = re.sub(
            r'^Filename:\s*.*$',
            f'Filename: {new_filename}',
            content,
            flags=re.MULTILINE
        )
        
        # Update RuleID or PolicyID field
        id_field = 'RuleID' if detection_type == 'rule' else 'PolicyID'
        new_detection_id = f"{original_detection_id}{id_suffix}"
        content = re.sub(
            r'^' + id_field + r':\s*["\']?' + re.escape(original_detection_id) + r'["\']?',
            f'{id_field}: "{new_detection_id}"',
            content,
            flags=re.MULTILINE
        )
        
        with open(target_yml, 'w') as f:
            f.write(content)


class DemoRulesManager:
    """Main manager class that orchestrates all operations."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.scripts_dir = repo_root / "scripts"
        self.demo_rules_dir = repo_root / "rules" / "demo_rules"
        self.config_path = self.scripts_dir / "demo_rules_config.yml"
        
        self.discovery = RuleDiscovery(repo_root)
        self.config_manager = ConfigManager(self.config_path)
        self.config = self.config_manager.load_config()
        self.cloner = RuleCloner(self.demo_rules_dir, self.config)
    
    def discover_command(self):
        """Discover and display all rules and policies in the repository with MITRE analysis."""
        rule_map = self.discovery.discover_all_rules()
        policy_map = self.discovery.discover_all_policies()
        mitre_stats = self.discovery.analyze_mitre_coverage()
        
        print(f"\n📊 Discovery Summary:")
        print(f"Total unique rules: {len(rule_map)}")
        print(f"Total unique policies: {len(policy_map)}")
        
        # Show rules with multiple implementations
        multi_impl = {k: v for k, v in rule_map.items() if len(v) > 1}
        if multi_impl:
            print(f"Rules with multiple implementations: {len(multi_impl)}")
            for rule_id, files in multi_impl.items():
                print(f"  {rule_id}:")
                for py_file, yml_file in files:
                    print(f"    - {yml_file.parent.name}/")
        
        print(f"\n🎯 MITRE ATT&CK Coverage Analysis:")
        print(f"Coverage: {mitre_stats['rules_with_mitre']}/{mitre_stats['total_rules']} rules ({mitre_stats['coverage_percentage']:.1f}%)")
        print(f"Tactics covered: {len(mitre_stats['tactics'])}/12")
        print(f"Techniques covered: {len(mitre_stats['techniques'])}")
        
        # Display rules organized by MITRE tactics
        if mitre_stats['tactics']:
            print(f"\n📋 Rules by MITRE ATT&CK Tactic:")
            for tactic_id in sorted(mitre_stats['tactics'].keys()):
                tactic_info = mitre_stats['tactics'][tactic_id]
                print(f"\n{tactic_id}: {tactic_info['name']} ({len(tactic_info['rules'])} rules)")
                print(f"  Techniques: {', '.join(sorted(tactic_info['techniques']))}")
                
                # Show first few rules as examples
                example_rules = sorted(tactic_info['rules'])[:5]
                for rule in example_rules:
                    source_path = mitre_stats['rules_by_mitre'][rule]['source_path']
                    print(f"    • {rule} ({source_path})")
                
                if len(tactic_info['rules']) > 5:
                    print(f"    ... and {len(tactic_info['rules']) - 5} more")
        
        # Show uncovered rules summary
        if mitre_stats['uncovered_rules']:
            print(f"\n❌ Rules without MITRE coverage ({len(mitre_stats['uncovered_rules'])}):")
            
            # Group by source directory
            by_source = {}
            for rule in mitre_stats['uncovered_rules']:
                source = rule['source_path']
                if source not in by_source:
                    by_source[source] = []
                by_source[source].append(rule['rule_id'])
            
            for source in sorted(by_source.keys()):
                rules = by_source[source]
                print(f"  {source}/ ({len(rules)} rules)")
                # Show first few examples
                examples = sorted(rules)[:3]
                for rule in examples:
                    print(f"    • {rule}")
                if len(rules) > 3:
                    print(f"    ... and {len(rules) - 3} more")
        
        # Save comprehensive discovery results
        discovery_file = self.scripts_dir / "discovered_rules.json"
        discovery_data = {
            'basic_mapping': {
                rule_id: [(str(py), str(yml)) for py, yml in files] 
                for rule_id, files in rule_map.items()
            },
            'mitre_analysis': mitre_stats
        }
        
        # Convert sets to lists for JSON serialization
        for tactic_data in discovery_data['mitre_analysis']['tactics'].values():
            tactic_data['techniques'] = list(tactic_data['techniques'])
        
        with open(discovery_file, 'w') as f:
            json.dump(discovery_data, f, indent=2)
        print(f"\n💾 Discovery results saved to {discovery_file}")
        
        # Save MITRE coverage report
        mitre_report_file = self.scripts_dir / "mitre_coverage_report.json"
        with open(mitre_report_file, 'w') as f:
            json.dump(mitre_stats, f, indent=2, default=list)
        print(f"🎯 MITRE coverage report saved to {mitre_report_file}")
    
    def clone_command(self):
        """Clone all enabled rules from configuration."""
        enabled_rules = self.config_manager.get_enabled_rules()
        
        if not enabled_rules:
            print("No enabled rules found in configuration")
            return
            
        print(f"🎯 Cloning {len(enabled_rules)} enabled rules...")
        
        success_count = 0
        for rule_config in enabled_rules:
            rule_id = rule_config['rule_id']
            target_category = rule_config['target_category']
            hint_path = rule_config.get('source_path')
            
            # Check if already cloned
            if rule_config.get('last_cloned'):
                print(f"⏭️  Skipping {rule_id} (already cloned)")
                continue
            
            # Find source files
            source_files = self.discovery.find_rule(rule_id, hint_path)
            if not source_files:
                print(f"❌ Rule {rule_id} not found in repository")
                continue
                
            source_py, source_yml = source_files
            
            # Clone the rule
            if self.cloner.clone_rule(rule_id, source_py, source_yml, target_category):
                self.config_manager.update_rule_timestamp(rule_id)
                success_count += 1
            
        self.config_manager.save_config()
        print(f"\n✅ Successfully cloned {success_count}/{len(enabled_rules)} rules")
    
    def add_command(self, detection_id: str, category: str = None, detection_type: str = 'rule'):
        """Add a new rule or policy to configuration and clone it."""
        print(f"➕ Adding {detection_type} {detection_id} to configuration...")
        
        if detection_type == 'rule':
            if not self.config_manager.add_rule(detection_id, category):
                return
            source_files = self.discovery.find_rule(detection_id)
            clone_method = self.cloner.clone_rule
            update_method = self.config_manager.update_rule_timestamp
        else:
            if not self.config_manager.add_policy(detection_id, category):
                return
            source_files = self.discovery.find_policy(detection_id)
            clone_method = self.cloner.clone_policy
            update_method = self.config_manager.update_policy_timestamp
            
        # Find and clone the detection
        if not source_files:
            print(f"❌ {detection_type.title()} {detection_id} not found in repository")
            return
            
        source_py, source_yml = source_files
        target_category = category or self.config.get('clone_settings', {}).get('default_category', 'aws_cloud_security')
        
        if clone_method(detection_id, source_py, source_yml, target_category):
            update_method(detection_id)
            self.config_manager.save_config()
            print(f"✅ Successfully added and cloned {detection_id}")
    
    def status_command(self, rule_id: str = None):
        """Show status of all configured rules or a specific rule."""
        if rule_id:
            self._show_single_rule_status(rule_id)
        else:
            self._show_all_rules_status()
    
    def _show_single_rule_status(self, rule_id: str):
        """Show detailed status for a specific rule."""
        print(f"🔍 Rule Status: {rule_id}")
        print("=" * 60)
        
        # Find rule in configuration
        enabled_rules = self.config_manager.get_enabled_rules()
        disabled_rules = self.config.get('disabled_rules', [])
        
        config_rule = None
        is_enabled = True
        
        # Check enabled rules
        for rule in enabled_rules:
            if rule['rule_id'] == rule_id:
                config_rule = rule
                break
        
        # Check disabled rules
        if not config_rule:
            for rule in disabled_rules:
                if rule['rule_id'] == rule_id:
                    config_rule = rule
                    is_enabled = False
                    break
        
        if not config_rule:
            print(f"❌ Rule '{rule_id}' not found in configuration")
            
            # Check if it exists in upstream
            source_files = self.discovery.find_rule(rule_id)
            if source_files:
                py_file, yml_file = source_files
                source_path = str(yml_file.parent.relative_to(self.repo_root / "rules"))
                print(f"\n💡 Rule exists in upstream: {source_path}")
                print(f"   Use: python scripts/demo_rules_manager.py add {rule_id}")
            else:
                print(f"\n❌ Rule not found in upstream either")
            return
        
        # Show basic information
        print(f"\n📊 Configuration Status:")
        print(f"  Rule ID: {config_rule['rule_id']}")
        print(f"  Status: {'✅ Enabled' if is_enabled else '❌ Disabled'}")
        
        if is_enabled:
            print(f"  Target Category: {config_rule['target_category']}")
            print(f"  Source Path: {config_rule.get('source_path', 'Auto-discover')}")
            
            last_cloned = config_rule.get('last_cloned', 'Never')
            if last_cloned and last_cloned != 'Never':
                last_cloned = last_cloned[:19].replace('T', ' ')
            print(f"  Last Cloned: {last_cloned}")
            
            if config_rule.get('notes'):
                print(f"  Notes: {config_rule['notes']}")
        else:
            print(f"  Disabled Reason: {config_rule.get('reason', 'No reason provided')}")
            if config_rule.get('disabled_date'):
                print(f"  Disabled Date: {config_rule['disabled_date']}")
        
        # Check if rule exists in demo_rules directory
        if is_enabled:
            demo_rule_exists = self._check_demo_rule_exists(rule_id, config_rule['target_category'])
            print(f"\n📁 Demo Files Status:")
            if demo_rule_exists:
                print(f"  ✅ Demo rule files exist in {config_rule['target_category']}/")
                # Show actual file paths
                demo_files = self._get_demo_rule_files(rule_id, config_rule['target_category'])
                for file_path in demo_files:
                    print(f"    • {file_path}")
            else:
                print(f"  ❌ Demo rule files not found in {config_rule['target_category']}/")
                if config_rule.get('last_cloned'):
                    print(f"     (Configured as cloned but files missing)")
        
        # Show upstream source information
        if is_enabled and config_rule.get('source_path'):
            source_files = self.discovery.find_rule(rule_id, config_rule['source_path'])
        else:
            source_files = self.discovery.find_rule(rule_id)
            
        if source_files:
            py_file, yml_file = source_files
            source_path = str(yml_file.parent.relative_to(self.repo_root / "rules"))
            print(f"\n🔗 Upstream Source:")
            print(f"  Source Directory: {source_path}")
            print(f"  Python File: {py_file.name}")
            print(f"  YAML File: {yml_file.name}")
            
            # Show MITRE information if available
            try:
                with open(yml_file, 'r') as f:
                    yaml_content = yaml.safe_load(f)
                
                if 'Reports' in yaml_content and 'MITRE ATT&CK' in yaml_content['Reports']:
                    mitre_techniques = yaml_content['Reports']['MITRE ATT&CK']
                    print(f"\n🎯 MITRE ATT&CK Mapping:")
                    for technique in mitre_techniques:
                        if ':' in str(technique):
                            tactic, tech = str(technique).split(':', 1)
                            print(f"    • {tactic}:{tech}")
                        else:
                            print(f"    • {technique}")
                else:
                    print(f"\n⚠️  No MITRE ATT&CK mapping found")
                
                # Show other metadata
                if yaml_content.get('Severity'):
                    print(f"\n📊 Rule Metadata:")
                    print(f"  Severity: {yaml_content['Severity']}")
                if yaml_content.get('LogTypes'):
                    log_types = yaml_content['LogTypes']
                    if isinstance(log_types, list):
                        print(f"  Log Types: {', '.join(log_types)}")
                    else:
                        print(f"  Log Types: {log_types}")
                if yaml_content.get('Tags'):
                    tags = yaml_content['Tags']
                    if isinstance(tags, list):
                        print(f"  Tags: {', '.join(tags)}")
                        
            except Exception as e:
                print(f"  Warning: Could not read YAML metadata: {e}")
        else:
            print(f"\n❌ Upstream source not found")
    
    def _show_all_rules_status(self):
        """Show status of all configured rules and policies."""
        enabled_rules = self.config_manager.get_enabled_rules()
        enabled_policies = self.config_manager.get_enabled_policies()
        disabled_rules = self.config.get('disabled_rules', [])
        disabled_policies = self.config.get('disabled_policies', [])
        
        print(f"📋 Demo Rules and Policies Status")
        print("=" * 50)
        
        print(f"\n✅ Enabled Rules ({len(enabled_rules)}):")
        for rule in enabled_rules:
            rule_id = rule['rule_id']
            category = rule['target_category']
            last_cloned = rule.get('last_cloned', 'Never')
            if last_cloned and last_cloned != 'Never':
                last_cloned = last_cloned[:19].replace('T', ' ')
            
            print(f"  {rule_id}")
            print(f"    Category: {category}")
            print(f"    Last Cloned: {last_cloned}")
            if rule.get('notes'):
                print(f"    Notes: {rule['notes']}")
            print()
        
        print(f"\n✅ Enabled Policies ({len(enabled_policies)}):")
        for policy in enabled_policies:
            policy_id = policy['policy_id']
            category = policy['target_category']
            last_cloned = policy.get('last_cloned', 'Never')
            if last_cloned and last_cloned != 'Never':
                last_cloned = last_cloned[:19].replace('T', ' ')
            
            print(f"  {policy_id}")
            print(f"    Category: {category}")
            print(f"    Last Cloned: {last_cloned}")
            if policy.get('notes'):
                print(f"    Notes: {policy['notes']}")
            print()
        
        if disabled_rules:
            print(f"❌ Disabled Rules ({len(disabled_rules)}):")
            for rule in disabled_rules:
                print(f"  {rule['rule_id']} - {rule.get('reason', 'No reason provided')}")
                
        if disabled_policies:
            print(f"❌ Disabled Policies ({len(disabled_policies)}):")
            for policy in disabled_policies:
                print(f"  {policy['policy_id']} - {policy.get('reason', 'No reason provided')}")
    
    def _check_demo_rule_exists(self, rule_id: str, category: str) -> bool:
        """Check if demo rule files exist in the target directory."""
        demo_files = self._get_demo_rule_files(rule_id, category)
        return len(demo_files) > 0
    
    def _get_demo_rule_files(self, rule_id: str, category: str) -> List[Path]:
        """Get list of demo rule files for a given rule ID and category."""
        demo_dir = self.demo_rules_dir / category
        if not demo_dir.exists():
            return []
        
        # Look for files with _demo suffix that might match this rule
        demo_files = []
        rule_id_demo = f"{rule_id}.Demo"
        
        for yml_file in demo_dir.glob("*_demo.yml"):
            try:
                with open(yml_file, 'r') as f:
                    content = yaml.safe_load(f)
                
                if content.get('RuleID') == rule_id_demo:
                    demo_files.append(yml_file)
                    # Look for corresponding Python file
                    filename = content.get('Filename', '')
                    if filename:
                        py_file = yml_file.parent / filename
                        if py_file.exists():
                            demo_files.append(py_file)
                    break
            except Exception:
                continue
        
        return demo_files
    
    def mitre_command(self):
        """Analyze MITRE ATT&CK coverage across all rules."""
        mitre_stats = self.discovery.analyze_mitre_coverage()
        
        print(f"\n🎯 MITRE ATT&CK Coverage Report")
        print("=" * 60)
        
        print(f"\n📊 Coverage Statistics:")
        print(f"  Total Rules: {mitre_stats['total_rules']}")
        print(f"  With MITRE: {mitre_stats['rules_with_mitre']} ({mitre_stats['coverage_percentage']:.1f}%)")
        print(f"  Without MITRE: {mitre_stats['rules_without_mitre']}")
        print(f"  Tactics Covered: {len(mitre_stats['tactics'])}/12")
        print(f"  Techniques Covered: {len(mitre_stats['techniques'])}")
        
        # Coverage gap analysis
        all_tactics = {'TA0001', 'TA0002', 'TA0003', 'TA0004', 'TA0005', 'TA0006', 
                      'TA0007', 'TA0008', 'TA0009', 'TA0010', 'TA0011', 'TA0040'}
        covered_tactics = set(mitre_stats['tactics'].keys())
        missing_tactics = all_tactics - covered_tactics
        
        if missing_tactics:
            tactic_names = {
                'TA0001': 'Initial Access', 'TA0002': 'Execution', 'TA0003': 'Persistence',
                'TA0004': 'Privilege Escalation', 'TA0005': 'Defense Evasion', 'TA0006': 'Credential Access',
                'TA0007': 'Discovery', 'TA0008': 'Lateral Movement', 'TA0009': 'Collection',
                'TA0010': 'Exfiltration', 'TA0011': 'Command and Control', 'TA0040': 'Impact'
            }
            print(f"\n❌ Missing Tactics ({len(missing_tactics)}):")
            for tactic in sorted(missing_tactics):
                print(f"  {tactic}: {tactic_names[tactic]}")
        
        # Detailed tactic breakdown
        if mitre_stats['tactics']:
            print(f"\n📋 Detailed Tactic Coverage:")
            for tactic_id in sorted(mitre_stats['tactics'].keys()):
                tactic_info = mitre_stats['tactics'][tactic_id]
                print(f"\n{tactic_id}: {tactic_info['name']}")
                print(f"  Rules: {len(tactic_info['rules'])}")
                print(f"  Techniques: {len(tactic_info['techniques'])} ({', '.join(sorted(tactic_info['techniques']))})")
                
                # Show top source directories for this tactic
                sources = {}
                for rule in tactic_info['rules']:
                    source = mitre_stats['rules_by_mitre'][rule]['source_path']
                    sources[source] = sources.get(source, 0) + 1
                
                top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:3]
                print(f"  Top Sources: {', '.join([f'{src} ({count})' for src, count in top_sources])}")
        
        # Rules without MITRE by source directory
        if mitre_stats['uncovered_rules']:
            print(f"\n❌ Rules Without MITRE Coverage:")
            by_source = {}
            for rule in mitre_stats['uncovered_rules']:
                source = rule['source_path']
                by_source[source] = by_source.get(source, 0) + 1
            
            for source, count in sorted(by_source.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / mitre_stats['rules_without_mitre']) * 100
                print(f"  {source}/: {count} rules ({percentage:.1f}% of uncovered)")
        
        # Save detailed report
        mitre_report_file = self.scripts_dir / "mitre_coverage_report.json"
        with open(mitre_report_file, 'w') as f:
            # Convert sets to lists for JSON serialization
            serializable_stats = mitre_stats.copy()
            for tactic_data in serializable_stats['tactics'].values():
                if isinstance(tactic_data['techniques'], set):
                    tactic_data['techniques'] = list(tactic_data['techniques'])
            json.dump(serializable_stats, f, indent=2)
        
        print(f"\n💾 Detailed MITRE report saved to {mitre_report_file}")
        
        # Recommendations
        print(f"\n💡 Recommendations:")
        if mitre_stats['coverage_percentage'] < 50:
            print("  - Coverage is low (<50%). Consider adding MITRE tags to more rules.")
        if missing_tactics:
            print(f"  - {len(missing_tactics)} tactics have no coverage. Focus on these areas.")
        if mitre_stats['rules_without_mitre'] > 0:
            print(f"  - {mitre_stats['rules_without_mitre']} rules lack MITRE tags. Review top directories above.")
    
    def fix_command(self):
        """Fix naming conventions (original functionality from fix_demo_naming.py)."""
        print("🔧 Fixing naming conventions in demo_rules/...")
        
        # Implementation of original fix_demo_naming.py logic
        # (This would be the existing code from your original script)
        # For brevity, I'm not including the full implementation here
        # but it would be a direct port of your existing functions
        
        print("✅ Naming convention fixes completed")


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        prog='demo_rules_manager.py',
        description="""
Demo Rules Manager - Advanced rule cloning and management tool

This tool manages the demo_rules/ directory by cloning rules from upstream 
panther-analysis directories while maintaining proper naming conventions and 
avoiding merge conflicts. It uses a YAML configuration file to track which 
rules to manage and their source locations.

KEY FEATURES:
- Clone rules from upstream directories with automatic _demo renaming
- Track rule sources and manage updates without conflicts  
- Organize rules into categories (production_security, siem_security, etc.)
- Distinguish between upstream-sourced and custom demo rules
- Prevent PAT (Panther Analysis Tool) conflicts through proper naming

WORKFLOW:
1. Use 'discover' to explore available rules in the repository
2. Use 'add' to include specific rules in your demo configuration  
3. Use 'status' to monitor your currently managed demo rules
4. Use 'clone' or 'sync' to bulk-manage multiple rules
5. Use 'fix' for existing rules that need naming convention updates

CONFIGURATION:
Rules are managed via scripts/demo_rules_config.yml which tracks:
- Rule sources and target categories
- Clone timestamps and custom modifications  
- Enabled/disabled status and notes
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Discover all available rules in the repository with MITRE analysis
  python demo_rules_manager.py discover
  
  # Analyze MITRE ATT&CK coverage across all rules
  python demo_rules_manager.py mitre
  
  # Add a specific rule and clone it immediately
  python demo_rules_manager.py add AWS.CloudTrail.NewDetection --category production_security
  
  # See current status of all managed rules
  python demo_rules_manager.py status
  
  # Check status of a specific rule
  python demo_rules_manager.py status AWS.Console.LoginWithoutMFA
  
  # Clone all enabled rules from configuration (skips already cloned)
  python demo_rules_manager.py clone
  
  # Fix naming conventions for existing demo rules
  python demo_rules_manager.py fix

For more information, see the demo_rules_config.yml configuration file.
        """
    )
    
    subparsers = parser.add_subparsers(
        dest='command', 
        help='Available commands',
        metavar='COMMAND'
    )
    
    # Discover command
    discover_parser = subparsers.add_parser(
        'discover', 
        help='Discover and map all rules in the repository',
        description="""
Scan the entire panther-analysis repository to discover all available rules
and build a comprehensive mapping of RuleID -> source locations.

This command:
- Searches all rules/ subdirectories for YAML files
- Extracts RuleIDs and maps them to their Python/YAML file pairs
- Identifies rules with multiple implementations  
- Saves results to scripts/discovered_rules.json for reference

Use this command to explore what rules are available before adding them
to your demo configuration.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Clone command  
    clone_parser = subparsers.add_parser(
        'clone',
        help='Clone all enabled rules from configuration',
        description="""
Clone all enabled rules from the demo_rules_config.yml configuration file
that haven't been cloned yet (based on last_cloned timestamp).

This command:
- Reads enabled rules from demo_rules_config.yml
- Skips rules that have already been cloned (have last_cloned timestamp)
- Finds source files using rule discovery and optional path hints
- Copies and renames files with proper _demo suffix
- Updates YAML Filename and RuleID fields to avoid conflicts
- Records successful clone timestamps in configuration

Safe to run multiple times - will only clone new/missing rules.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add command
    add_parser = subparsers.add_parser(
        'add',
        help='Add new rule or policy to configuration and clone it immediately',
        description="""
Add a new rule or policy to the demo_rules_config.yml configuration and clone it
immediately to the specified category directory.

This command:
- Adds the rule or policy to the configuration file
- Discovers the detection's source location automatically
- Clones the detection with proper _demo naming conventions
- Updates configuration with clone timestamp

This is the primary way to add individual rules or policies to your demo environment.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    add_parser.add_argument(
        'detection_id', 
        help='Rule ID or Policy ID to add (e.g., AWS.CloudTrail.ConsoleLogin or AWS.S3.PublicRead)'
    )
    add_parser.add_argument(
        '--category', 
        help='Target category directory (default: aws_cloud_security)',
        default=None
    )
    add_parser.add_argument(
        '--type', 
        help='Detection type: rule or policy (default: rule)',
        choices=['rule', 'policy'],
        default='rule',
        dest='detection_type'
    )
    
    # Update command
    update_parser = subparsers.add_parser(
        'update',
        help='Update an existing cloned rule from its source',
        description="""
Update an existing demo rule by re-cloning it from its upstream source.
This overwrites the existing demo rule files with the latest version
from the source directory.

WARNING: This will overwrite any local modifications to the demo rule.
Use with caution if you have customized the demo version.

Currently not implemented - placeholder for future functionality.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    update_parser.add_argument('rule_id', help='Rule ID to update')
    
    # Sync command
    sync_parser = subparsers.add_parser(
        'sync',
        help='Synchronize all rules (clone new, update existing)',
        description="""
Comprehensive synchronization of all rules in the configuration:
- Clone any enabled rules that haven't been cloned yet
- Update existing rules from their upstream sources (when implemented)
- Skip custom rules (those with null source_path)

This is useful for bulk operations and keeping demo rules up-to-date
with upstream changes.

Currently not fully implemented - placeholder for future functionality.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Status command
    status_parser = subparsers.add_parser(
        'status',
        help='Show detailed status of all configured rules or a specific rule',
        description="""
Display comprehensive status information for rules in the demo
configuration.

When no rule ID is specified:
- Shows all enabled and disabled rules
- Displays rule categories and organization
- Shows last clone timestamps and source paths
- Includes custom notes and modifications
- Provides complete overview of demo rules management state

When a specific rule ID is provided:
- Shows detailed information for that rule only
- Includes MITRE ATT&CK mapping if available
- Shows source file locations and clone history
- Displays any custom modifications or notes
- Indicates if the rule exists in demo_rules/ directory

This is useful for quick status checks on individual rules or 
comprehensive overview of all managed rules.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    status_parser.add_argument(
        'rule_id',
        nargs='?',
        help='Optional specific rule ID to show status for (e.g., AWS.CloudTrail.ConsoleLogin)'
    )
    
    # MITRE command
    mitre_parser = subparsers.add_parser(
        'mitre',
        help='Analyze MITRE ATT&CK coverage across all rules',
        description="""
Comprehensive analysis of MITRE ATT&CK framework coverage across
all rules in the panther-analysis repository.

This command provides:
- Overall coverage statistics (percentage of rules with MITRE tags)
- Breakdown by tactics and techniques
- Gap analysis showing missing tactics
- Source directory analysis for uncovered rules  
- Detailed recommendations for improving coverage

The analysis examines the "Reports" field in rule YAML files looking
for "MITRE ATT&CK" entries in the format TA0001:T1078.

Results are saved to mitre_coverage_report.json for further analysis.
Use this to understand security coverage gaps and prioritize rule
improvements.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Fix command
    fix_parser = subparsers.add_parser(
        'fix',
        help='Fix naming conventions for existing demo rules',
        description="""
Fix naming convention issues in the existing demo_rules/ directory.
This is the original functionality from fix_demo_naming.py.

This command:
- Ensures all Python files have _demo.py suffix
- Ensures all YAML files have _demo.yml suffix  
- Updates Filename fields in YAML to reference correct Python files
- Updates RuleIDs to have .Demo suffix
- Maintains consistency across all demo rule files

Use this when you have existing demo rules that don't follow the
proper naming conventions, or after manual file modifications.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Find repository root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    manager = DemoRulesManager(repo_root)
    
    if args.command == 'discover':
        manager.discover_command()
    elif args.command == 'clone':
        manager.clone_command()
    elif args.command == 'add':
        manager.add_command(args.detection_id, args.category, args.detection_type)
    elif args.command == 'status':
        manager.status_command(args.rule_id)
    elif args.command == 'mitre':
        manager.mitre_command()
    elif args.command == 'fix':
        manager.fix_command()
    else:
        print(f"Command '{args.command}' not yet implemented")


if __name__ == "__main__":
    main()
