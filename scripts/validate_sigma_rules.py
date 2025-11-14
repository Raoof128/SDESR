#!/usr/bin/env python3
"""
Sigma Rule Validation Script
Validates Sigma YAML rules for syntax correctness and required fields.

Usage:
    python validate_sigma_rules.py <rules_directory>
    python validate_sigma_rules.py rules/

Author: SIEM Detection Engineering Portfolio
Date: 2025-11-14
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Tuple
import re


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'


class SigmaRuleValidator:
    """Validates Sigma rules according to official specification"""

    REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'logsource', 'detection']
    OPTIONAL_FIELDS = ['references', 'author', 'date', 'modified', 'tags', 'falsepositives', 'level', 'fields']

    VALID_STATUSES = ['stable', 'test', 'experimental', 'deprecated']
    VALID_LEVELS = ['critical', 'high', 'medium', 'low', 'informational']

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.rules_validated = 0
        self.rules_passed = 0
        self.rules_failed = 0

    def validate_rule_file(self, file_path: Path) -> Tuple[bool, List[str], List[str]]:
        """
        Validate a single Sigma rule file

        Args:
            file_path: Path to the Sigma YAML file

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        errors = []
        warnings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)

            if not rule_data:
                errors.append("Empty YAML file")
                return False, errors, warnings

            # Check required fields
            for field in self.REQUIRED_FIELDS:
                if field not in rule_data:
                    errors.append(f"Missing required field: '{field}'")

            # Validate UUID format
            if 'id' in rule_data:
                uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
                if not re.match(uuid_pattern, str(rule_data['id'])):
                    errors.append(f"Invalid UUID format for 'id': {rule_data['id']}")

            # Validate status
            if 'status' in rule_data:
                if rule_data['status'] not in self.VALID_STATUSES:
                    errors.append(f"Invalid status '{rule_data['status']}'. Must be one of {self.VALID_STATUSES}")

            # Validate level
            if 'level' in rule_data:
                if rule_data['level'] not in self.VALID_LEVELS:
                    errors.append(f"Invalid level '{rule_data['level']}'. Must be one of {self.VALID_LEVELS}")

            # Validate logsource
            if 'logsource' in rule_data:
                logsource = rule_data['logsource']
                if not isinstance(logsource, dict):
                    errors.append("'logsource' must be a dictionary")
                else:
                    # Should have at least one of: product, service, category
                    if not any(key in logsource for key in ['product', 'service', 'category']):
                        warnings.append("'logsource' should contain at least one of: product, service, category")

            # Validate detection
            if 'detection' in rule_data:
                detection = rule_data['detection']
                if not isinstance(detection, dict):
                    errors.append("'detection' must be a dictionary")
                else:
                    # Must have 'condition'
                    if 'condition' not in detection:
                        errors.append("'detection' must contain 'condition' field")

                    # Should have at least one selection
                    has_selection = any(key.startswith('selection') or key.startswith('filter')
                                       for key in detection.keys() if key != 'condition')
                    if not has_selection:
                        warnings.append("'detection' should contain at least one selection or filter")

            # Validate tags format
            if 'tags' in rule_data:
                if not isinstance(rule_data['tags'], list):
                    errors.append("'tags' must be a list")
                else:
                    for tag in rule_data['tags']:
                        if not isinstance(tag, str):
                            errors.append(f"Tag must be string: {tag}")
                        # Check for MITRE ATT&CK format
                        if tag.startswith('attack.t'):
                            attack_pattern = r'^attack\.t\d{4}(\.\d{3})?$'
                            if not re.match(attack_pattern, tag):
                                warnings.append(f"MITRE ATT&CK tag may be malformed: {tag}")

            # Check for recommended fields
            if 'author' not in rule_data:
                warnings.append("Recommended field 'author' is missing")

            if 'references' not in rule_data:
                warnings.append("Recommended field 'references' is missing")

            if 'falsepositives' not in rule_data:
                warnings.append("Recommended field 'falsepositives' is missing")

            # Title should be descriptive (at least 10 characters)
            if 'title' in rule_data and len(str(rule_data['title'])) < 10:
                warnings.append("Title seems too short (< 10 characters)")

            # Description should be detailed (at least 50 characters)
            if 'description' in rule_data and len(str(rule_data['description'])) < 50:
                warnings.append("Description seems too short (< 50 characters)")

            is_valid = len(errors) == 0
            return is_valid, errors, warnings

        except yaml.YAMLError as e:
            errors.append(f"YAML parsing error: {str(e)}")
            return False, errors, warnings
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")
            return False, errors, warnings

    def validate_directory(self, rules_dir: Path) -> Dict:
        """
        Validate all Sigma rules in a directory recursively

        Args:
            rules_dir: Path to directory containing Sigma rules

        Returns:
            Dictionary with validation results
        """
        results = {
            'total_files': 0,
            'passed': 0,
            'failed': 0,
            'details': []
        }

        print(f"{Colors.BOLD}Validating Sigma rules in: {rules_dir}{Colors.END}\n")

        # Find all YAML files
        yaml_files = list(rules_dir.rglob('*.yml')) + list(rules_dir.rglob('*.yaml'))

        # Exclude README files
        yaml_files = [f for f in yaml_files if not f.name.lower().startswith('readme')]

        if not yaml_files:
            print(f"{Colors.YELLOW}No Sigma rule files found (.yml or .yaml){Colors.END}")
            return results

        for yaml_file in sorted(yaml_files):
            results['total_files'] += 1
            relative_path = yaml_file.relative_to(rules_dir)

            is_valid, errors, warnings = self.validate_rule_file(yaml_file)

            if is_valid:
                results['passed'] += 1
                print(f"{Colors.GREEN}✓ PASS{Colors.END} - {relative_path}")
                if warnings:
                    for warning in warnings:
                        print(f"  {Colors.YELLOW}⚠ WARNING:{Colors.END} {warning}")
            else:
                results['failed'] += 1
                print(f"{Colors.RED}✗ FAIL{Colors.END} - {relative_path}")
                for error in errors:
                    print(f"  {Colors.RED}ERROR:{Colors.END} {error}")
                if warnings:
                    for warning in warnings:
                        print(f"  {Colors.YELLOW}WARNING:{Colors.END} {warning}")

            results['details'].append({
                'file': str(relative_path),
                'valid': is_valid,
                'errors': errors,
                'warnings': warnings
            })

        return results

    def print_summary(self, results: Dict):
        """Print validation summary"""
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}VALIDATION SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{'='*60}{Colors.END}")

        total = results['total_files']
        passed = results['passed']
        failed = results['failed']

        print(f"Total files:    {total}")
        print(f"{Colors.GREEN}Passed:         {passed} ({passed/total*100:.1f}%){Colors.END}")

        if failed > 0:
            print(f"{Colors.RED}Failed:         {failed} ({failed/total*100:.1f}%){Colors.END}")
        else:
            print(f"Failed:         {failed}")

        # Count total warnings
        total_warnings = sum(len(d['warnings']) for d in results['details'])
        if total_warnings > 0:
            print(f"{Colors.YELLOW}Total warnings: {total_warnings}{Colors.END}")

        print(f"{Colors.BOLD}{'='*60}{Colors.END}\n")

        if failed == 0 and total > 0:
            print(f"{Colors.GREEN}{Colors.BOLD}🎉 All Sigma rules are valid!{Colors.END}")
            return 0
        elif failed > 0:
            print(f"{Colors.RED}{Colors.BOLD}❌ {failed} rule(s) failed validation{Colors.END}")
            return 1
        else:
            print(f"{Colors.YELLOW}No rules found to validate{Colors.END}")
            return 2


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rules_directory>")
        print(f"Example: {sys.argv[0]} rules/")
        sys.exit(1)

    rules_dir = Path(sys.argv[1])

    if not rules_dir.exists():
        print(f"{Colors.RED}Error: Directory not found: {rules_dir}{Colors.END}")
        sys.exit(1)

    if not rules_dir.is_dir():
        print(f"{Colors.RED}Error: Not a directory: {rules_dir}{Colors.END}")
        sys.exit(1)

    validator = SigmaRuleValidator()
    results = validator.validate_directory(rules_dir)
    exit_code = validator.print_summary(results)

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
