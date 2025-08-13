#!/usr/bin/env python3
"""
Simple Stratus Red Team Orchestrator
Warmup credential access and impact techniques, cleanup all techniques.
"""
import subprocess
import sys
import argparse
from typing import List, Optional


# Techniques for warmup
WARMUP_TECHNIQUES = [
    "aws.credential-access.secretsmanager-retrieve-secrets",
    "aws.impact.s3-ransomware-batch-deletion"
]

# All techniques for cleanup
ALL_TECHNIQUES = [
    "aws.credential-access.secretsmanager-retrieve-secrets",
    "aws.persistence.iam-create-admin-user",
    "aws.impact.s3-ransomware-batch-deletion"
]


def run_stratus_command(stratus_path: str, action: str, technique_id: str) -> Optional[subprocess.CompletedProcess]:
    """Execute a Stratus Red Team command"""
    command = [stratus_path, action, technique_id]
    
    print(f"[*] Executing: {' '.join(command)}")
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.stdout and result.stdout.strip():
            print(f"[+] Output:\n{result.stdout}")
            
        if result.stderr and result.stderr.strip():
            print(f"[!] Errors:\n{result.stderr}")
            
        return result
        
    except Exception as e:
        print(f"[-] Error executing command: {e}")
        return None


def warmup_techniques(stratus_path: str):
    """Warmup credential access and impact techniques"""
    print("Warming up credential access and impact techniques...")
    print("=" * 50)
    
    for technique_id in WARMUP_TECHNIQUES:
        print(f"\n[*] Warming up: {technique_id}")
        result = run_stratus_command(stratus_path, "warmup", technique_id)
        
        if result and result.returncode == 0:
            print(f"[+] Success: {technique_id}")
        else:
            print(f"[-] Failed: {technique_id}")


def cleanup_all_techniques(stratus_path: str):
    """Cleanup all techniques"""
    print("Cleaning up all techniques...")
    print("=" * 50)
    
    # Cleanup in reverse order
    for technique_id in reversed(ALL_TECHNIQUES):
        print(f"\n[*] Cleaning up: {technique_id}")
        result = run_stratus_command(stratus_path, "cleanup", technique_id)
        
        if result and result.returncode == 0:
            print(f"[+] Success: {technique_id}")
        else:
            print(f"[-] Failed: {technique_id}")


def main():
    parser = argparse.ArgumentParser(description="Simple Stratus Red Team Orchestrator")
    parser.add_argument(
        "--stratus-path", 
        required=True,
        help="Path to the stratus binary"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    subparsers.add_parser('warmup', help='Warmup credential access and impact techniques')
    subparsers.add_parser('cleanup', help='Cleanup all techniques')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    print(f"Using Stratus binary: {args.stratus_path}")
    print()
    
    if args.command == 'warmup':
        warmup_techniques(args.stratus_path)
    elif args.command == 'cleanup':
        cleanup_all_techniques(args.stratus_path)
    
    print("\nDone.")


if __name__ == "__main__":
    main()
