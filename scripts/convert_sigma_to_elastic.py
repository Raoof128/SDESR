#!/usr/bin/env python3
"""
Sigma to Elastic KQL Converter
Converts Sigma detection rules to Elastic Kibana Query Language (KQL).

Usage:
    python convert_sigma_to_elastic.py <rules_directory> [output_file]
    python convert_sigma_to_elastic.py rules/ conversions/elastic/all_rules.json

Author: SIEM Detection Engineering Portfolio
Date: 2025-11-14
"""

import os
import sys
import yaml
import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime


class SigmaToElasticConverter:
    """Converts Sigma rules to Elastic KQL queries"""

    def __init__(self):
        self.converted_rules = []

    def map_logsource_to_index(self, logsource: Dict) -> str:
        """Map Sigma logsource to Elastic index pattern"""
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        category = logsource.get('category', '').lower()

        # Map common logsources to Elastic indexes
        if product == 'windows':
            if service == 'sysmon':
                return 'winlogbeat-* OR sysmon-*'
            elif service == 'security':
                return 'winlogbeat-*'
            else:
                return 'winlogbeat-*'

        elif category == 'process_creation':
            return 'winlogbeat-*'
        elif category == 'network_connection':
            return 'packetbeat-* OR winlogbeat-*'
        elif category == 'dns':
            return 'packetbeat-* OR dns-*'
        elif category == 'proxy':
            return 'filebeat-* OR proxy-*'
        elif category == 'firewall':
            return 'filebeat-* OR firewall-*'
        elif category == 'file_event':
            return 'winlogbeat-*'
        elif category == 'registry_event':
            return 'winlogbeat-*'

        return '*'

    def convert_field_name(self, field: str) -> str:
        """Convert Sigma field names to ECS (Elastic Common Schema) field names"""
        ecs_mapping = {
            'CommandLine': 'process.command_line',
            'Image': 'process.executable',
            'ParentImage': 'process.parent.executable',
            'ParentCommandLine': 'process.parent.command_line',
            'TargetFilename': 'file.path',
            'TargetObject': 'registry.path',
            'TargetImage': 'process.target.executable',
            'SourceImage': 'process.executable',
            'User': 'user.name',
            'DestinationIp': 'destination.ip',
            'DestinationPort': 'destination.port',
            'SourceIp': 'source.ip',
            'SourcePort': 'source.port',
            'EventID': 'event.code',
            'GrantedAccess': 'process.granted_access',
            'ProcessId': 'process.pid',
            'query': 'dns.question.name',
            'answer': 'dns.answers',
            'method': 'http.request.method',
            'uri_path': 'url.path'
        }

        return ecs_mapping.get(field, field.lower())

    def convert_modifier(self, field: str, modifier: str, value) -> str:
        """Convert Sigma field modifiers to KQL syntax"""
        ecs_field = self.convert_field_name(field)

        if modifier == 'contains':
            if isinstance(value, list):
                conditions = [f'{ecs_field}:*{v}*' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{ecs_field}:*{value}*'

        elif modifier == 'startswith':
            if isinstance(value, list):
                conditions = [f'{ecs_field}:{v}*' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{ecs_field}:{value}*'

        elif modifier == 'endswith':
            if isinstance(value, list):
                conditions = [f'{ecs_field}:*{v}' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{ecs_field}:*{value}'

        elif modifier == 're':
            # KQL doesn't support regex directly, approximate with wildcard
            return f'{ecs_field}:*'

        else:
            # Default: exact match
            if isinstance(value, list):
                conditions = [f'{ecs_field}:"{v}"' for v in value]
                return f"({' OR '.join(conditions)})"
            return f'{ecs_field}:"{value}"'

    def convert_selection(self, selection_name: str, selection: Dict) -> str:
        """Convert a Sigma selection to KQL conditions"""
        conditions = []

        for field_expr, value in selection.items():
            # Handle field modifiers (e.g., "CommandLine|contains")
            if '|' in field_expr:
                field, modifier = field_expr.split('|', 1)
                condition = self.convert_modifier(field, modifier, value)
            else:
                # No modifier - exact match
                ecs_field = self.convert_field_name(field_expr)
                if isinstance(value, list):
                    conditions_list = [f'{ecs_field}:"{v}"' for v in value]
                    condition = f"({' OR '.join(conditions_list)})"
                else:
                    condition = f'{ecs_field}:"{value}"'

            conditions.append(condition)

        return ' AND '.join(conditions) if conditions else ''

    def convert_detection(self, detection: Dict) -> str:
        """Convert Sigma detection logic to KQL"""
        condition = detection.get('condition', '')

        # Convert each selection and filter
        for key, value in detection.items():
            if key == 'condition':
                continue

            if isinstance(value, dict):
                converted = self.convert_selection(key, value)
                if converted:
                    condition = condition.replace(key, f'({converted})')

        # Handle simple "and" and "or" conditions
        condition = condition.replace(' and ', ' AND ')
        condition = condition.replace(' or ', ' OR ')
        condition = condition.replace(' not ', ' NOT ')

        return condition

    def convert_rule(self, rule_path: Path) -> Dict:
        """Convert a single Sigma rule to Elastic detection rule"""
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
            tags = rule.get('tags', [])

            # Build KQL query
            index_pattern = self.map_logsource_to_index(logsource)
            kql_query = self.convert_detection(detection)

            # Map severity
            severity_mapping = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low',
                'informational': 'low'
            }
            severity = severity_mapping.get(level, 'medium')

            # Build Elastic detection rule JSON
            detection_rule = {
                "name": title,
                "description": description,
                "risk_score": {"critical": 99, "high": 75, "medium": 50, "low": 25}.get(level, 50),
                "severity": severity,
                "type": "query",
                "query": kql_query,
                "index": index_pattern.split(' OR '),
                "language": "kuery",
                "tags": tags,
                "enabled": True,
                "from": "now-360s",
                "interval": "5m",
                "max_signals": 100,
                "references": rule.get('references', []),
                "false_positives": rule.get('falsepositives', []),
                "threat": self.build_threat_framework(tags)
            }

            return {
                'rule': detection_rule,
                'title': title,
                'file': rule_path.name
            }

        except Exception as e:
            print(f"Error converting {rule_path}: {e}", file=sys.stderr)
            return None

    def build_threat_framework(self, tags: List[str]) -> List[Dict]:
        """Build MITRE ATT&CK framework mappings from tags"""
        threat = []

        # Extract MITRE ATT&CK techniques from tags
        attack_tags = [tag for tag in tags if tag.startswith('attack.t')]

        for tag in attack_tags:
            technique_id = tag.replace('attack.t', 'T').upper()

            threat.append({
                "framework": "MITRE ATT&CK",
                "technique": [
                    {
                        "id": technique_id,
                        "name": f"Technique {technique_id}",
                        "reference": f"https://attack.mitre.org/techniques/{technique_id}/"
                    }
                ]
            })

        return threat

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

    def write_elastic_rules(self, converted_rules: List[Dict], output_file: Path):
        """Write converted Elastic rules to JSON file"""
        rules_array = [r['rule'] for r in converted_rules]

        output_data = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "total_rules": len(converted_rules),
                "description": "Sigma detection rules converted to Elastic Security detection rules"
            },
            "rules": rules_array
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)

        print(f"✓ Converted {len(converted_rules)} rules to: {output_file}")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rules_directory> [output_file]")
        print(f"Example: {sys.argv[0]} rules/ conversions/elastic/all_rules.json")
        sys.exit(1)

    rules_dir = Path(sys.argv[1])
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('sigma_rules_elastic.json')

    if not rules_dir.exists() or not rules_dir.is_dir():
        print(f"Error: Invalid rules directory: {rules_dir}")
        sys.exit(1)

    # Create output directory if needed
    output_file.parent.mkdir(parents=True, exist_ok=True)

    converter = SigmaToElasticConverter()
    converted_rules = converter.convert_directory(rules_dir)

    if not converted_rules:
        print("No rules converted. Check your input directory.")
        sys.exit(1)

    converter.write_elastic_rules(converted_rules, output_file)
    print(f"\n✓ Successfully converted {len(converted_rules)} Sigma rules to Elastic KQL")
    print(f"\nTo import into Kibana:")
    print(f"  1. Go to Security → Detections → Manage Rules")
    print(f"  2. Click 'Import rules'")
    print(f"  3. Select the generated JSON file")


if __name__ == '__main__':
    main()
