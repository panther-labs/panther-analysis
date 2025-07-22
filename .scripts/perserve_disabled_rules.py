import os
from pathlib import Path
import yaml
import shutil
import re

def get_rules(directory):
    '''Gets all current panther rules'''
    directory_path = Path(directory)
    rules = []
    for file_path in directory_path.rglob('*'):
     if file_path.is_file() and file_path.name.endswith(".yml"):
        rules.append(str(file_path))
    return rules

def read_yaml_and_get_disabled_rules(rules):
    '''Reads a list of rules and returns rules that are currently disabled'''
    disabled_rules = []
    for file_path in rules:
        with open(file_path, "r") as file:
            data = yaml.safe_load(file)
            if data.get("Enabled") == False:
                disabled_rules.append(file_path)
    return disabled_rules

def update_panther_analysis_rules(src_dir, dst_dir, disabled_rules):
    '''Gets the updated panther analysis rules and preserves the disabled rules by overwriting the rules/ directory'''
    exclusions = {".git"}

    for rule in disabled_rules:
        new_rule = f"{src_dir}{rule}"
        handle_rule_to_preserve(new_rule)

    for item in os.listdir(src_dir):
        if item in exclusions:
            continue
        src_path = os.path.join(src_dir, item)
        dst_path = os.path.join(dst_dir, item)

        if os.path.isdir(src_path):
            shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
        else:
            shutil.copy2(src_path, dst_path)

def handle_rule_to_preserve(src_path):
    '''Modifies the rule to be disabled'''
    key_to_update = 'Enabled'
    new_value = 'false'

    # Regex to match the exact line starting with `Enabled:`
    pattern = re.compile(rf'^({re.escape(key_to_update)}\s*:\s*)\S+', re.IGNORECASE)

    with open(src_path, 'r') as f:
        lines = f.readlines()

    with open(src_path, 'w') as f:
        for line in lines:
            if pattern.match(line):
                line = pattern.sub(rf'\1{new_value}', line)
            f.write(line)

def main():
    #Get current rules and disabled rules
    current_rules = get_rules("./rules/")
    disabled_rules = read_yaml_and_get_disabled_rules(current_rules)

    #Get updated rules from upstream and preserve disabled rules
    update_panther_analysis_rules("./panther-analysis-latest-release/", "./", disabled_rules)

if __name__ == "__main__":
    main()

