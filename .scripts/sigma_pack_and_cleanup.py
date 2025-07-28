import os
from pathlib import Path
import yaml


def check_for_collisions(rules):
    panther_rules = get_rules(directory= "./rules")
    bad_rules = []
    for key in rules.keys():
        if key in panther_rules.keys():
            print(f"Collision found: {key}")
            handle_collision(rules[key])
            bad_rules.append(key)

    #Remove collisions from sigma rules and return new values
    for rule in bad_rules:
        rules.pop(rule)
    return rules

def handle_collision(rule):
    Path(rule).unlink()
    

def get_rules(directory):
    directory_path = Path(directory)
    rules = {}
    for file_path in directory_path.rglob('*'):
        if file_path.is_file() and "sigma" not in file_path.parent.name:
            rules[file_path.name] = file_path
    return rules

def create_pack(rules):
    pack_ids = []
    for key in rules.keys():
        if ".yml" in key:
            id_name = key.split(".")[0]
            pack_ids.append(id_name)


    log_types = ["Standard.AWS.CloudTrail", "Standard.GCP.AuditLog", "Standard.Github.Audit", "Standard.Okta.SystemLog"]
    pack_ids = sorted(pack_ids) + log_types

    pack = {
        "AnalysisType": "pack",
        "PackID": "AlchemyManaged.Sigma.Custom",
        "Description": "Group of all Alchemy Sigma detections",
        "PackDefinition": {
            "IDs": pack_ids
        },
        "DisplayName": "'Sigma Rules Coverted by Alchemy'"
    }

    class IndentDumper(yaml.SafeDumper):
        def increase_indent(self, flow=False, indentless=False):
            return super().increase_indent(flow, False)

    pack_yaml = yaml.dump(pack, Dumper=IndentDumper, sort_keys=False)
    with open("./packs/alchemy_sigma.yml", "w") as f:
        f.write(pack_yaml)

def main():
    #Check for collisions
    sigma_rules = get_rules(directory= "./temp_rules/")
    sigma_rules = check_for_collisions(sigma_rules)

    #Create pack
    pack = create_pack(sigma_rules) 

if __name__ == "__main__":
    main()