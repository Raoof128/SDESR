# Contributing to SIEM Detection Engineering Portfolio

Thank you for your interest in contributing! This document provides guidelines for contributing detection rules and improvements.

---

## How to Contribute

### 1. Reporting Issues

**Bug Reports:**
- Use the Bug Report template
- Include rule ID and affected SIEM platform
- Provide steps to reproduce
- Include log samples if possible

**False Positives:**
- Use the False Positive Report template
- Describe the legitimate activity triggering the alert
- Suggest filter modifications
- Indicate frequency and business impact

### 2. Submitting New Rules

**Rule Requirements:**
- Must be in valid Sigma format (YAML)
- Must include all required fields:
  - `title`: Descriptive rule name
  - `id`: Valid UUID v4
  - `status`: stable/test/experimental
  - `description`: Detailed explanation
  - `logsource`: Specify product/service/category
  - `detection`: Detection logic with condition
  - `level`: critical/high/medium/low
  - `tags`: MITRE ATT&CK mappings

**Testing:**
```bash
# Validate your rule
python3 scripts/validate_sigma_rules.py path/to/your/rule.yml

# Test conversion
python3 scripts/convert_sigma_to_splunk.py path/to/your/rule.yml
python3 scripts/convert_sigma_to_elastic.py path/to/your/rule.yml
```

**Documentation:**
- Add README.md to rule category folder
- Document expected false positives
- Include testing scenarios
- Map to MITRE ATT&CK techniques

### 3. Pull Request Process

1. **Fork the repository**

2. **Create a feature branch:**
   ```bash
   git checkout -b feature/new-detection-rule
   ```

3. **Make your changes:**
   - Add/modify Sigma rules
   - Update documentation
   - Add tests if applicable

4. **Validate everything:**
   ```bash
   python3 scripts/validate_sigma_rules.py rules/
   ```

5. **Commit with clear messages:**
   ```bash
   git commit -m "Add detection rule for XYZ technique (T1234)"
   ```

6. **Push and create PR:**
   ```bash
   git push origin feature/new-detection-rule
   ```

7. **PR Description should include:**
   - Summary of changes
   - MITRE ATT&CK technique(s) covered
   - Testing performed
   - False positive analysis
   - Any breaking changes

### 4. Code Style

**Sigma Rules:**
- Use 2-space indentation
- Follow SigmaHQ field naming conventions
- Use descriptive selection names (`selection_cmd_line`, not `sel1`)
- Add meaningful comments for complex logic

**Python Scripts:**
- Follow PEP 8
- Add docstrings to functions
- Include type hints where appropriate
- Use meaningful variable names

**Documentation:**
- Use Markdown format
- Include code examples
- Provide clear step-by-step instructions
- Keep language concise and technical

### 5. Testing Requirements

**For New Detection Rules:**
- [ ] Rule validates with `validate_sigma_rules.py`
- [ ] Converts successfully to Splunk SPL
- [ ] Converts successfully to Elastic KQL
- [ ] Tested against Atomic Red Team (if applicable)
- [ ] False positive rate documented
- [ ] Detection latency measured

**For Code Changes:**
- [ ] Python scripts run without errors
- [ ] Existing tests pass
- [ ] New tests added for new functionality

### 6. MITRE ATT&CK Mapping

All detection rules must map to MITRE ATT&CK:

```yaml
tags:
  - attack.credential_access    # Tactic
  - attack.t1003.001            # Technique
  - detection.endpoint          # Platform
```

**Verify technique IDs:**
- Check https://attack.mitre.org/
- Ensure technique is current (not deprecated)
- Include sub-technique when applicable

### 7. Performance Considerations

**Rules should be optimized for:**
- Low false positive rate (<2% target)
- Fast detection latency (<10 seconds target)
- Efficient SIEM query execution
- Minimal resource consumption

**Avoid:**
- Overly broad detections
- Expensive regex operations
- Unnecessary field extractions
- Hardcoded values that should be configurable

### 8. Security Considerations

**Never commit:**
- Actual credentials or API keys
- Internal IP addresses or hostnames
- Proprietary detection logic
- Real incident data

**Do commit:**
- Generic examples
- Sanitized test data
- Public threat intelligence
- Open-source detection patterns

---

## Rule Categories

When adding new rules, place in appropriate category:

- `credential_dumping/` - T1003, T1555, T1110
- `lateral_movement/` - T1021, T1570, T1135
- `persistence/` - T1547, T1053, T1546
- `privilege_escalation/` - T1134, T1548, T1055
- `command_control/` - T1071, T1095, T1571
- `defense_evasion/` - T1562, T1070 (future)
- `discovery/` - T1087, T1083 (future)
- `collection/` - T1056, T1113 (future)
- `exfiltration/` - T1048, T1041 (future)

---

## Recognition

Contributors will be recognized in:
- Rule author fields
- README.md contributors section
- Release notes

---

## Questions?

- Open an issue for questions
- Reference existing rules as examples
- Check SigmaHQ documentation: https://github.com/SigmaHQ/sigma

---

## Code of Conduct

- Be respectful and professional
- Focus on technical merit
- Provide constructive feedback
- Help others learn and improve

---

**Thank you for contributing to better detection engineering!** 🚀
