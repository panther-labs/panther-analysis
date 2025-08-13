#!/usr/bin/env python3
"""
Script to ensure all rules in rules/demo_rules/ follow the _demo naming convention.

This script will:
1. Find all Python files in rules/demo_rules/ that don't end with _demo.py
2. Rename them to add the _demo suffix
3. Update the corresponding YAML files' Filename field to match
4. Rename YAML files to match the new Python filenames
"""

import os
import sys
import re
import yaml
from pathlib import Path


def find_demo_rules_directory():
    """Find the demo rules directory relative to script location."""
    script_dir = Path(__file__).parent
    demo_rules_dir = script_dir.parent / "rules" / "demo_rules"
    
    if not demo_rules_dir.exists():
        print(f"Error: Demo rules directory not found at {demo_rules_dir}")
        sys.exit(1)
    
    return demo_rules_dir


def get_python_files_needing_rename(demo_rules_dir):
    """Find all Python files that don't have _demo suffix."""
    files_to_rename = []
    
    for py_file in demo_rules_dir.rglob("*.py"):
        if not py_file.name.endswith("_demo.py"):
            files_to_rename.append(py_file)
    
    return files_to_rename


def get_yaml_files_needing_update(demo_rules_dir):
    """Find all YAML files that need their Filename field updated."""
    files_to_update = []
    
    for yaml_file in demo_rules_dir.rglob("*.yml"):
        try:
            with open(yaml_file, 'r') as f:
                content = yaml.safe_load(f)
                
            if 'Filename' in content:
                filename = content['Filename']
                # Check if the referenced Python file doesn't have _demo suffix
                if filename.endswith('.py') and not filename.endswith('_demo.py'):
                    files_to_update.append((yaml_file, filename))
        except Exception as e:
            print(f"Warning: Could not read {yaml_file}: {e}")
    
    return files_to_update


def rename_python_file(py_file):
    """Rename a Python file to add _demo suffix."""
    # Get the base name without .py extension
    base_name = py_file.stem
    new_name = f"{base_name}_demo.py"
    new_path = py_file.parent / new_name
    
    print(f"Renaming: {py_file.name} -> {new_name}")
    py_file.rename(new_path)
    return new_path


def update_yaml_filename_field(yaml_file, old_filename):
    """Update the Filename field in a YAML file."""
    try:
        with open(yaml_file, 'r') as f:
            content = f.read()
        
        # Get base name and add _demo suffix
        base_name = old_filename.replace('.py', '')
        new_filename = f"{base_name}_demo.py"
        
        # Replace the Filename field
        updated_content = re.sub(
            r'^Filename:\s*' + re.escape(old_filename),
            f'Filename: {new_filename}',
            content,
            flags=re.MULTILINE
        )
        
        if updated_content != content:
            with open(yaml_file, 'w') as f:
                f.write(updated_content)
            print(f"Updated Filename field in {yaml_file.name}: {old_filename} -> {new_filename}")
            return new_filename
        
    except Exception as e:
        print(f"Error updating {yaml_file}: {e}")
    
    return None


def rename_yaml_file_if_needed(yaml_file):
    """Rename YAML file to match its Python counterpart if needed."""
    if not yaml_file.name.endswith("_demo.yml"):
        # Get the base name without .yml extension
        base_name = yaml_file.stem
        new_name = f"{base_name}_demo.yml"
        new_path = yaml_file.parent / new_name
        
        print(f"Renaming: {yaml_file.name} -> {new_name}")
        yaml_file.rename(new_path)
        return new_path
    
    return yaml_file


def main():
    """Main function to fix all demo naming issues."""
    print("🔧 Demo Rules Naming Convention Fixer")
    print("=" * 50)
    
    demo_rules_dir = find_demo_rules_directory()
    print(f"Working in: {demo_rules_dir}")
    print()
    
    # Step 1: Find and rename Python files that need _demo suffix
    python_files_to_rename = get_python_files_needing_rename(demo_rules_dir)
    
    if python_files_to_rename:
        print(f"📋 Found {len(python_files_to_rename)} Python files to rename:")
        for py_file in python_files_to_rename:
            print(f"  - {py_file.relative_to(demo_rules_dir)}")
        print()
        
        for py_file in python_files_to_rename:
            rename_python_file(py_file)
        print()
    else:
        print("✅ All Python files already have _demo suffix")
        print()
    
    # Step 2: Find and update YAML files with incorrect Filename references
    yaml_files_to_update = get_yaml_files_needing_update(demo_rules_dir)
    
    if yaml_files_to_update:
        print(f"📋 Found {len(yaml_files_to_update)} YAML files with incorrect Filename fields:")
        for yaml_file, filename in yaml_files_to_update:
            print(f"  - {yaml_file.relative_to(demo_rules_dir)}: {filename}")
        print()
        
        for yaml_file, old_filename in yaml_files_to_update:
            update_yaml_filename_field(yaml_file, old_filename)
        print()
    else:
        print("✅ All YAML Filename fields already reference _demo.py files")
        print()
    
    # Step 3: Rename YAML files to match Python files
    yaml_files_needing_rename = []
    for yaml_file in demo_rules_dir.rglob("*.yml"):
        if not yaml_file.name.endswith("_demo.yml"):
            yaml_files_needing_rename.append(yaml_file)
    
    if yaml_files_needing_rename:
        print(f"📋 Found {len(yaml_files_needing_rename)} YAML files to rename:")
        for yaml_file in yaml_files_needing_rename:
            print(f"  - {yaml_file.relative_to(demo_rules_dir)}")
        print()
        
        for yaml_file in yaml_files_needing_rename:
            rename_yaml_file_if_needed(yaml_file)
        print()
    else:
        print("✅ All YAML files already have _demo suffix")
        print()
    
    print("🎉 Demo naming convention fix completed!")
    print("\nNext steps:")
    print("1. Run 'make lint' to verify no issues")
    print("2. Run 'pipenv run panther_analysis_tool test --path rules/demo_rules/' to verify tests pass")
    print("3. Review changes and commit if everything looks good")


if __name__ == "__main__":
    main()