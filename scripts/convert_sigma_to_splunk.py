#!/usr/bin/env python3
"""
Sigma to Splunk SPL Converter
Converts Sigma detection rules to Splunk Search Processing Language (SPL).

Usage:
    python convert_sigma_to_splunk.py <rules_directory> [output_file]
    python convert_sigma_to_splunk.py rules/ conversions/splunk/all_rules.spl

Author: SIEM Detection Engineering Portfolio
Date: 2025-11-14
"""

import os
import sys
import yaml
from pathlib import Path
from typing import Dict, List
from datetime import datetime


class SigmaToSplunkConverter:
    """Converts Sigma rules to Splunk SPL queries"""

    def __init__(self):
        self.converted_rules = []

    def map_logsource_to_index(self, logsource: Dict) -> str:
        """Map Sigma logsource to Splunk index"""
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        category = logsource.get('category', '').lower()

        # Map common logsources to Splunk indexes
        if product == 'windows':
            if service == 'sysmon':
                return 'index=sysmon'
            elif service == 'security':
                return 'index=windows EventCode=*'
            elif service in ['system', 'application']:
                return f'index=windows source="WinEventLog:{service.title()}"'
            else:
                return 'index=windows OR index=sysmon'

        elif category == 'process_creation':
            return 'index=sysmon EventCode=1'
        elif category == 'network_connection':
            return 'index=sysmon EventCode=3'
        elif category == 'dns':
            return 'index=dns OR (index=sysmon EventCode=22)'
        elif category == 'proxy':
            return 'index=proxy'
        elif category == 'firewall':
            return 'index=firewall'
        elif category == 'file_event':
            return 'index=sysmon EventCode=11'
        elif category == 'registry_event':
            return 'index=sysmon EventCode=13'

        return 'index=*'

    def convert_field_name(self, field: str) -> str:
        """Convert Sigma field names to Splunk field names"""
        field_mapping = {
            'CommandLine': 'CommandLine',
            'Image': 'Image',
            'ParentImage': 'ParentImage',
            'ParentCommandLine': 'ParentCommandLine',
            'TargetFilename': 'TargetFilename',
            'TargetObject': 'TargetObject',
            'TargetImage': 'TargetImage',
            'SourceImage': 'SourceImage',
            'User': 'User',
            'DestinationIp': 'DestinationIp',
            'DestinationPort': 'DestinationPort',
            'SourceIp': 'SourceIp',
            'SourcePort': 'SourcePort',
            'EventID': 'EventCode',
            'GrantedAccess': 'GrantedAccess',
            'ProcessId': 'ProcessId',
            'query': 'query',
            'answer': 'answer',
            'method': 'http_method'
        }

        return field_mapping.get(field, field)

    def convert_modifier(self, field: str, modifier: str, value: str) -> str:
        """Convert Sigma field modifiers to SPL syntax"""
        spl_field = self.convert_field_name(field)

        if modifier == 'contains':
            if isinstance(value, list):
                conditions = [f'{spl_field}="*{v}*"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{spl_field}="*{value}*"'

        elif modifier == 'startswith':
            if isinstance(value, list):
                conditions = [f'{spl_field}="{v}*"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{spl_field}="{value}*"'

        elif modifier == 'endswith':
            if isinstance(value, list):
                conditions = [f'{spl_field}="*{v}"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{spl_field}="*{value}"'

        elif modifier == 're':
            return f'rex field={spl_field} "{value}"'

        else:
            # Default: exact match
            if isinstance(value, list):
                values = ', '.join([f'"{v}"' for v in value])
                return f'{spl_field} IN ({values})'
            return f'{spl_field}="{value}"'

    def convert_selection(self, selection_name: str, selection: Dict) -> str:
        """Convert a Sigma selection to SPL conditions"""
        conditions = []

        for field_expr, value in selection.items():
            # Handle field modifiers (e.g., "CommandLine|contains")
            if '|' in field_expr:
                field, modifier = field_expr.split('|', 1)
                condition = self.convert_modifier(field, modifier, value)
            else:
                # No modifier - exact match
                field = self.convert_field_name(field_expr)
                if isinstance(value, list):
                    values = ', '.join([f'"{v}"' for v in value])
                    condition = f'{field} IN ({values})'
                else:
                    condition = f'{field}="{value}"'

            conditions.append(condition)

        return ' AND '.join(conditions) if conditions else ''

    def convert_detection(self, detection: Dict) -> str:
        """Convert Sigma detection logic to SPL"""
        spl_parts = []

        # Extract condition
        condition = detection.get('condition', '')

        # Convert each selection and filter
        for key, value in detection.items():
            if key == 'condition':
                continue

            if isinstance(value, dict):
                converted = self.convert_selection(key, value)
                if converted:
                    # Store for later use in condition
                    condition = condition.replace(key, f'({converted})')

        # Handle simple "and" and "or" conditions
        condition = condition.replace(' and ', ' AND ')
        condition = condition.replace(' or ', ' OR ')
        condition = condition.replace(' not ', ' NOT ')

        return condition

    def convert_rule(self, rule_path: Path) -> Dict:
        """Convert a single Sigma rule to Splunk SPL"""
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)

            if not rule:
                return None

            title = rule.get('title', 'Untitled')
            description = rule.get('description', '').replace('\n', ' ').strip()
            level = rule.get('level', 'medium')
            logsource = rule.get('logsource', {})
            detection = rule.get('detection', {})

            # Build SPL query
            index_clause = self.map_logsource_to_index(logsource)
            detection_clause = self.convert_detection(detection)

            # Build full SPL search
            spl_query = f'''{index_clause}
{detection_clause}
| stats count by _time, host, User, Image, CommandLine
| sort -count'''

            return {
                'title': title,
                'description': description,
                'level': level,
                'spl': spl_query,
                'file': rule_path.name
            }

        except Exception as e:
            print(f"Error converting {rule_path}: {e}", file=sys.stderr)
            return None

    def convert_directory(self, rules_dir: Path) -> List[Dict]:
        """Convert all Sigma rules in a directory"""
        yaml_files = list(rules_dir.rglob('*.yml')) + list(rules_dir.rglob('*.yaml'))
        yaml_files = [f for f in yaml_files if not f.name.lower().startswith('readme')]

        converted = []
        for yaml_file in sorted(yaml_files):
            result = self.convert_rule(yaml_file)
            if result:
                converted.append(result)

        return converted

    def write_splunk_queries(self, converted_rules: List[Dict], output_file: Path):
        """Write converted SPL queries to file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# Sigma Rules Converted to Splunk SPL\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total Rules: {len(converted_rules)}\n")
            f.write("#" + "="*70 + "\n\n")

            for i, rule in enumerate(converted_rules, 1):
                f.write(f"#" + "-"*70 + "\n")
                f.write(f"# Rule {i}: {rule['title']}\n")
                f.write(f"# Level: {rule['level']}\n")
                f.write(f"# Source: {rule['file']}\n")
                f.write(f"# Description: {rule['description'][:100]}...\n")
                f.write(f"#" + "-"*70 + "\n\n")
                f.write(rule['spl'])
                f.write("\n\n\n")

        print(f"✓ Converted {len(converted_rules)} rules to: {output_file}")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rules_directory> [output_file]")
        print(f"Example: {sys.argv[0]} rules/ conversions/splunk/all_rules.spl")
        sys.exit(1)

    rules_dir = Path(sys.argv[1])
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('sigma_rules_splunk.spl')

    if not rules_dir.exists() or not rules_dir.is_dir():
        print(f"Error: Invalid rules directory: {rules_dir}")
        sys.exit(1)

    # Create output directory if needed
    output_file.parent.mkdir(parents=True, exist_ok=True)

    converter = SigmaToSplunkConverter()
    converted_rules = converter.convert_directory(rules_dir)

    if not converted_rules:
        print("No rules converted. Check your input directory.")
        sys.exit(1)

    converter.write_splunk_queries(converted_rules, output_file)
    print(f"\n✓ Successfully converted {len(converted_rules)} Sigma rules to Splunk SPL")


if __name__ == '__main__':
    main()
