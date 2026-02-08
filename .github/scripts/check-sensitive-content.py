#!/usr/bin/env python3
"""
Script to detect sensitive content in GitHub Actions workflow files.
Categorizes findings by severity level.
"""

import os
import re
import sys
import yaml
from pathlib import Path
from typing import List, Dict, Tuple
import json


class SeverityLevel:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# Patterns for detecting sensitive content
SENSITIVE_PATTERNS = [
    # CRITICAL - Hardcoded secrets/credentials
    {
        "pattern": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{3,}["\']',
        "severity": SeverityLevel.CRITICAL,
        "description": "Hardcoded password detected",
        "example": 'password: "mypassword123"'
    },
    {
        "pattern": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{10,}["\']',
        "severity": SeverityLevel.CRITICAL,
        "description": "Hardcoded API key detected",
        "example": 'api_key: "sk-1234567890abcdef"'
    },
    {
        "pattern": r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{10,}["\']',
        "severity": SeverityLevel.CRITICAL,
        "description": "Hardcoded secret key detected",
        "example": 'secret_key: "my-secret-value"'
    },
    {
        "pattern": r'(?i)(access[_-]?token|accesstoken)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{10,}["\']',
        "severity": SeverityLevel.CRITICAL,
        "description": "Hardcoded access token detected",
        "example": 'access_token: "ghp_1234567890"'
    },
    {
        "pattern": r'(?i)(private[_-]?key|privatekey)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{10,}["\']',
        "severity": SeverityLevel.CRITICAL,
        "description": "Hardcoded private key detected",
        "example": 'private_key: "-----BEGIN PRIVATE KEY-----"'
    },
    
    # HIGH - Potential credential leaks
    {
        "pattern": r'(?i)(bearer|authorization)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{10,}["\']',
        "severity": SeverityLevel.HIGH,
        "description": "Hardcoded authorization header detected",
        "example": 'Authorization: "Bearer token123"'
    },
    {
        "pattern": r'(?i)(client[_-]?secret|clientsecret)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{10,}["\']',
        "severity": SeverityLevel.HIGH,
        "description": "Hardcoded client secret detected",
        "example": 'client_secret: "mysecret123"'
    },
    {
        "pattern": r'(?i)(connection[_-]?string|connectionstring)\s*[:=]\s*["\'](?!.*\$\{|\$\(|{{)[^"\']{10,}["\']',
        "severity": SeverityLevel.HIGH,
        "description": "Hardcoded connection string detected",
        "example": 'connection_string: "Server=..."'
    },
    
    # MEDIUM - Secrets used but not properly marked
    {
        "pattern": r'(?i)echo\s+.*\$\{\{\s*secrets\.',
        "severity": SeverityLevel.MEDIUM,
        "description": "Secret value potentially echoed to logs",
        "example": 'echo ${{ secrets.MY_SECRET }}'
    },
    {
        "pattern": r'(?i)(curl|wget).*-H.*["\'].*\$\{\{\s*secrets\.',
        "severity": SeverityLevel.MEDIUM,
        "description": "Secret used in HTTP header (ensure proper masking)",
        "example": 'curl -H "Auth: ${{ secrets.TOKEN }}"'
    },
    
    # LOW - Best practice violations
    {
        "pattern": r'(?i)required:\s*false.*secrets\.',
        "severity": SeverityLevel.LOW,
        "description": "Secret marked as not required (should typically be required)",
        "example": 'secrets: MY_SECRET: required: false'
    },
    {
        "pattern": r'\$\{\{\s*github\.event\.inputs\.[^}]*password',
        "severity": SeverityLevel.LOW,
        "description": "Password passed as workflow input (consider using secrets instead)",
        "example": '${{ github.event.inputs.password }}'
    },
]


class SensitiveContentFinding:
    def __init__(self, file_path: str, line_number: int, line_content: str, 
                 severity: str, description: str, pattern: str):
        self.file_path = file_path
        self.line_number = line_number
        self.line_content = line_content.strip()
        self.severity = severity
        self.description = description
        self.pattern = pattern

    def to_dict(self):
        return {
            "file": self.file_path,
            "line": self.line_number,
            "content": self.line_content,
            "severity": self.severity,
            "description": self.description
        }


def scan_file(file_path: str) -> List[SensitiveContentFinding]:
    """Scan a single file for sensitive content."""
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, start=1):
            for pattern_info in SENSITIVE_PATTERNS:
                if re.search(pattern_info["pattern"], line):
                    finding = SensitiveContentFinding(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line,
                        severity=pattern_info["severity"],
                        description=pattern_info["description"],
                        pattern=pattern_info["pattern"]
                    )
                    findings.append(finding)
    except Exception as e:
        print(f"Error scanning {file_path}: {e}", file=sys.stderr)
    
    return findings


def scan_directory(directory: str, extensions: List[str] = None) -> List[SensitiveContentFinding]:
    """Scan all workflow files in a directory."""
    if extensions is None:
        extensions = ['.yml', '.yaml']
    
    findings = []
    path = Path(directory)
    
    for ext in extensions:
        for file_path in path.rglob(f'*{ext}'):
            file_findings = scan_file(str(file_path))
            findings.extend(file_findings)
    
    return findings


def categorize_findings(findings: List[SensitiveContentFinding]) -> Dict[str, List[SensitiveContentFinding]]:
    """Categorize findings by severity."""
    categorized = {
        SeverityLevel.CRITICAL: [],
        SeverityLevel.HIGH: [],
        SeverityLevel.MEDIUM: [],
        SeverityLevel.LOW: []
    }
    
    for finding in findings:
        categorized[finding.severity].append(finding)
    
    return categorized


def print_report(categorized_findings: Dict[str, List[SensitiveContentFinding]]):
    """Print a formatted report of findings."""
    total_findings = sum(len(findings) for findings in categorized_findings.values())
    
    if total_findings == 0:
        print("✅ No sensitive content detected in workflow files.")
        return
    
    print(f"\n⚠️  Found {total_findings} potential sensitive content issue(s) in workflow files:\n")
    
    severity_order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]
    
    for severity in severity_order:
        findings = categorized_findings[severity]
        if not findings:
            continue
        
        emoji = {
            SeverityLevel.CRITICAL: "🔴",
            SeverityLevel.HIGH: "🟠",
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.LOW: "🔵"
        }
        
        print(f"{emoji[severity]} {severity} ({len(findings)} finding(s)):")
        print("-" * 80)
        
        for finding in findings:
            print(f"  File: {finding.file_path}")
            print(f"  Line: {finding.line_number}")
            print(f"  Issue: {finding.description}")
            print(f"  Content: {finding.line_content[:100]}...")
            print()
    
    print("\n" + "=" * 80)
    print("\n📋 Summary:")
    print(f"  🔴 CRITICAL: {len(categorized_findings[SeverityLevel.CRITICAL])} - Immediate action required")
    print(f"  🟠 HIGH: {len(categorized_findings[SeverityLevel.HIGH])} - Should be addressed soon")
    print(f"  🟡 MEDIUM: {len(categorized_findings[SeverityLevel.MEDIUM])} - Review recommended")
    print(f"  🔵 LOW: {len(categorized_findings[SeverityLevel.LOW])} - Best practice improvement")
    print()


def save_json_report(categorized_findings: Dict[str, List[SensitiveContentFinding]], output_file: str):
    """Save findings to a JSON file."""
    report = {
        "total": sum(len(findings) for findings in categorized_findings.values()),
        "by_severity": {
            severity: [f.to_dict() for f in findings]
            for severity, findings in categorized_findings.items()
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📄 JSON report saved to: {output_file}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Scan GitHub Actions workflow files for sensitive content"
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory)"
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        help="Save results to JSON file"
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Fail (exit code 1) if issues of this severity or higher are found (default: high)"
    )
    
    args = parser.parse_args()
    
    # Scan for findings
    findings = scan_directory(args.directory)
    categorized = categorize_findings(findings)
    
    # Print report
    print_report(categorized)
    
    # Save JSON if requested
    if args.json_output:
        save_json_report(categorized, args.json_output)
    
    # Determine exit code based on fail-on level
    severity_levels = {
        "critical": [SeverityLevel.CRITICAL],
        "high": [SeverityLevel.CRITICAL, SeverityLevel.HIGH],
        "medium": [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM],
        "low": [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW]
    }
    
    fail_severities = severity_levels[args.fail_on]
    has_failing_issues = any(categorized[sev] for sev in fail_severities)
    
    if has_failing_issues:
        print(f"\n❌ Failing due to issues at {args.fail_on.upper()} severity or higher.")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
