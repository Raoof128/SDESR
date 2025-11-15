#!/usr/bin/env python3

"""
SIEM Detection Engineering Portfolio - Automated Test Runner
Version: 1.0.0

This script automates the testing and validation of Sigma detection rules by:
1. Validating Sigma rule syntax
2. Converting rules to Splunk SPL and Elastic KQL
3. Running detection tests against simulated attack data
4. Generating test reports with detection rates and FP analysis
"""

import os
import sys
import json
import csv
import yaml
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_header(title: str):
    """Print formatted section header"""
    width = 80
    print(f"\n{Colors.BLUE}{'=' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{title.center(width)}{Colors.RESET}")
    print(f"{Colors.BLUE}{'=' * width}{Colors.RESET}\n")

def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓{Colors.RESET} {message}")

def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}✗{Colors.RESET} {message}")

def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {message}")

def print_info(message: str):
    """Print info message"""
    print(f"{Colors.CYAN}ℹ{Colors.RESET} {message}")

class TestRunner:
    """Main test runner class"""

    def __init__(self, rules_dir: Path, output_dir: Path):
        self.rules_dir = Path(rules_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.results = {
            'validation': {'passed': 0, 'failed': 0, 'errors': []},
            'splunk_conversion': {'passed': 0, 'failed': 0, 'errors': []},
            'elastic_conversion': {'passed': 0, 'failed': 0, 'errors': []},
            'total_rules': 0
        }

    def find_sigma_rules(self) -> List[Path]:
        """Find all Sigma rule files"""
        rules = list(self.rules_dir.rglob('*.yml'))
        rules = [r for r in rules if not r.name.startswith('README')]
        return sorted(rules)

    def validate_sigma_rules(self) -> bool:
        """Validate all Sigma rules"""
        print_header("STEP 1: Validating Sigma Rules")

        script_path = self.rules_dir.parent / 'scripts' / 'validate_sigma_rules.py'

        if not script_path.exists():
            print_error(f"Validation script not found: {script_path}")
            return False

        try:
            result = subprocess.run(
                ['python3', str(script_path), str(self.rules_dir)],
                capture_output=True,
                text=True,
                timeout=60
            )

            print(result.stdout)

            if result.returncode == 0:
                self.results['validation']['passed'] = self.results['total_rules']
                print_success(f"All {self.results['total_rules']} rules validated successfully")
                return True
            else:
                print_error("Rule validation failed")
                self.results['validation']['errors'].append(result.stderr)
                return False

        except subprocess.TimeoutExpired:
            print_error("Validation timed out after 60 seconds")
            return False
        except Exception as e:
            print_error(f"Validation error: {str(e)}")
            return False

    def convert_to_splunk(self) -> bool:
        """Convert Sigma rules to Splunk SPL"""
        print_header("STEP 2: Converting to Splunk SPL")

        script_path = self.rules_dir.parent / 'scripts' / 'convert_sigma_to_splunk.py'
        output_file = self.output_dir / 'splunk_queries.spl'

        if not script_path.exists():
            print_error(f"Conversion script not found: {script_path}")
            return False

        try:
            result = subprocess.run(
                ['python3', str(script_path), str(self.rules_dir), str(output_file)],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                spl_lines = output_file.read_text().count('\n')
                self.results['splunk_conversion']['passed'] = self.results['total_rules']
                print_success(f"Converted {self.results['total_rules']} rules to Splunk SPL ({spl_lines} lines)")
                return True
            else:
                print_error("Splunk conversion failed")
                print_error(result.stderr)
                return False

        except subprocess.TimeoutExpired:
            print_error("Conversion timed out after 120 seconds")
            return False
        except Exception as e:
            print_error(f"Conversion error: {str(e)}")
            return False

    def convert_to_elastic(self) -> bool:
        """Convert Sigma rules to Elastic KQL"""
        print_header("STEP 3: Converting to Elastic KQL")

        script_path = self.rules_dir.parent / 'scripts' / 'convert_sigma_to_elastic.py'
        output_file = self.output_dir / 'elastic_rules.json'

        if not script_path.exists():
            print_error(f"Conversion script not found: {script_path}")
            return False

        try:
            result = subprocess.run(
                ['python3', str(script_path), str(self.rules_dir), str(output_file)],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                # Validate JSON structure
                with open(output_file, 'r') as f:
                    elastic_data = json.load(f)
                    rule_count = len(elastic_data.get('rules', []))

                self.results['elastic_conversion']['passed'] = rule_count
                print_success(f"Converted {rule_count} rules to Elastic KQL")
                return True
            else:
                print_error("Elastic conversion failed")
                print_error(result.stderr)
                return False

        except json.JSONDecodeError as e:
            print_error(f"Invalid JSON output: {str(e)}")
            return False
        except subprocess.TimeoutExpired:
            print_error("Conversion timed out after 120 seconds")
            return False
        except Exception as e:
            print_error(f"Conversion error: {str(e)}")
            return False

    def analyze_rule_coverage(self) -> Dict:
        """Analyze MITRE ATT&CK coverage"""
        print_header("STEP 4: Analyzing Detection Coverage")

        rules = self.find_sigma_rules()
        coverage = {
            'tactics': defaultdict(int),
            'techniques': set(),
            'severity': defaultdict(int)
        }

        for rule_file in rules:
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)

                # Extract MITRE ATT&CK tags
                tags = rule.get('tags', [])
                for tag in tags:
                    if tag.startswith('attack.t'):
                        technique_id = tag.replace('attack.', '').upper()
                        coverage['techniques'].add(technique_id)
                    elif tag.startswith('attack.') and not tag.startswith('attack.t'):
                        tactic = tag.replace('attack.', '').replace('_', ' ').title()
                        coverage['tactics'][tactic] += 1

                # Extract severity
                level = rule.get('level', 'medium')
                coverage['severity'][level] += 1

            except Exception as e:
                print_warning(f"Failed to analyze {rule_file.name}: {str(e)}")

        # Print coverage summary
        print_info(f"Total Techniques Covered: {len(coverage['techniques'])}")
        print_info(f"Tactics Covered: {len(coverage['tactics'])}")

        print(f"\n{Colors.BOLD}Coverage by Tactic:{Colors.RESET}")
        for tactic, count in sorted(coverage['tactics'].items(), key=lambda x: -x[1]):
            print(f"  {tactic}: {count} rules")

        print(f"\n{Colors.BOLD}Coverage by Severity:{Colors.RESET}")
        for severity, count in sorted(coverage['severity'].items()):
            print(f"  {severity.capitalize()}: {count} rules")

        return coverage

    def generate_test_report(self) -> Path:
        """Generate comprehensive test report"""
        print_header("STEP 5: Generating Test Report")

        report_file = self.output_dir / f'test_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_rules': self.results['total_rules'],
                'validation_passed': self.results['validation']['passed'],
                'splunk_conversion_passed': self.results['splunk_conversion']['passed'],
                'elastic_conversion_passed': self.results['elastic_conversion']['passed']
            },
            'detailed_results': self.results
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print_success(f"Test report saved to: {report_file}")
        return report_file

    def run_all_tests(self) -> bool:
        """Run all test phases"""
        start_time = datetime.now()

        print(f"\n{Colors.BOLD}SIEM Detection Engineering Portfolio - Test Runner{Colors.RESET}")
        print(f"{Colors.CYAN}Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}\n")

        # Find all rules
        rules = self.find_sigma_rules()
        self.results['total_rules'] = len(rules)

        if self.results['total_rules'] == 0:
            print_error(f"No Sigma rules found in {self.rules_dir}")
            return False

        print_info(f"Found {self.results['total_rules']} Sigma rules\n")

        # Run test phases
        all_passed = True

        if not self.validate_sigma_rules():
            all_passed = False

        if not self.convert_to_splunk():
            all_passed = False

        if not self.convert_to_elastic():
            all_passed = False

        # Analyze coverage
        self.analyze_rule_coverage()

        # Generate report
        self.generate_test_report()

        # Print summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        print_header("TEST SUMMARY")

        if all_passed:
            print_success(f"All tests passed! ({duration:.2f} seconds)")
            print_success(f"✓ Validation: {self.results['validation']['passed']}/{self.results['total_rules']}")
            print_success(f"✓ Splunk Conversion: {self.results['splunk_conversion']['passed']}/{self.results['total_rules']}")
            print_success(f"✓ Elastic Conversion: {self.results['elastic_conversion']['passed']}/{self.results['total_rules']}")
        else:
            print_error(f"Some tests failed ({duration:.2f} seconds)")
            print_info(f"Validation: {self.results['validation']['passed']}/{self.results['total_rules']}")
            print_info(f"Splunk Conversion: {self.results['splunk_conversion']['passed']}/{self.results['total_rules']}")
            print_info(f"Elastic Conversion: {self.results['elastic_conversion']['passed']}/{self.results['total_rules']}")

        return all_passed

def main():
    parser = argparse.ArgumentParser(
        description='SIEM Detection Engineering Portfolio - Automated Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'rules_dir',
        type=Path,
        help='Directory containing Sigma rules'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        default=Path('test_output'),
        help='Output directory for test results (default: test_output)'
    )

    args = parser.parse_args()

    if not args.rules_dir.exists():
        print_error(f"Rules directory not found: {args.rules_dir}")
        sys.exit(1)

    runner = TestRunner(args.rules_dir, args.output)
    success = runner.run_all_tests()

    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
