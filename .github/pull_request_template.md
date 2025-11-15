## Pull Request Description

**Type of Change:**
- [ ] New Sigma detection rule
- [ ] Enhancement to existing rule
- [ ] Bug fix (false positive reduction, detection bypass fix)
- [ ] Documentation update
- [ ] Script/automation improvement
- [ ] Lab environment enhancement
- [ ] Other (please describe):

**Summary:**
<!-- Provide a clear, concise description of your changes -->


---

## Detection Rule Changes (if applicable)

### Rule Information
- **Rule ID(s):**
- **Rule Name(s):**
- **MITRE ATT&CK Technique(s):**
- **Tactic(s):**
- **Severity Level:**

### Detection Logic
<!-- Briefly explain the detection logic and what malicious behavior it identifies -->


### False Positive Analysis
<!-- What legitimate activities might trigger this rule? How have you minimized false positives? -->


---

## Testing Performed

**Validation Checklist:**
- [ ] Sigma rule syntax validated (`validate_sigma_rules.py`)
- [ ] Successfully converts to Splunk SPL
- [ ] Successfully converts to Elastic KQL
- [ ] Tested against attack simulation (Atomic Red Team or equivalent)
- [ ] Tested against benign baseline traffic
- [ ] False positive rate measured: ______%
- [ ] Detection latency measured: ______s

**Test Environment:**
- SIEM Platform:
- Log Source:
- Test Dataset Size:

**Test Results:**
<!-- Paste test output or describe test results -->
```
# Example:
# Detection Rate: 10/10 (100%)
# False Positives: 2/1000 (0.2%)
# Mean Latency: 5.3 seconds
```

---

## Code Quality (for script/automation changes)

- [ ] Python code follows PEP 8
- [ ] Functions have docstrings
- [ ] Error handling implemented
- [ ] No hardcoded credentials or secrets
- [ ] Dependencies added to requirements.txt (if new)

---

## Documentation Updates

- [ ] README.md updated (if needed)
- [ ] CHANGELOG.md updated
- [ ] Rule-specific README created/updated
- [ ] MITRE ATT&CK mapping updated
- [ ] Comments added to complex code sections

---

## Breaking Changes

**Does this PR introduce breaking changes?**
- [ ] No
- [ ] Yes (please describe below)

<!-- If yes, describe the impact and migration steps -->


---

## MITRE ATT&CK Mapping Verification

**Technique ID(s):**
<!-- e.g., T1003.001, T1055.002 -->

**Verification:**
- [ ] Technique exists in current ATT&CK framework
- [ ] Technique is not deprecated
- [ ] Sub-technique used when applicable
- [ ] Tactic correctly aligned with technique

**ATT&CK Reference:**
<!-- Link to technique page, e.g., https://attack.mitre.org/techniques/T1003/001/ -->


---

## Performance Impact

**Expected Impact:**
- [ ] No performance impact
- [ ] Minimal impact (< 5% query time increase)
- [ ] Moderate impact (5-15% query time increase)
- [ ] Significant impact (> 15% query time increase)

**Justification:**
<!-- If moderate or significant impact, explain why it's necessary -->


---

## Deployment Considerations

**Platform Compatibility:**
- [ ] Splunk
- [ ] Elastic Security
- [ ] Other (specify):

**Special Requirements:**
<!-- Any special data sources, field mappings, or configurations needed? -->


---

## Related Issues

**Closes:** #
**Related to:** #

---

## Screenshots (if applicable)

<!-- Add screenshots of SIEM alerts, test results, or dashboards -->


---

## Checklist

Before submitting this PR, please ensure:

- [ ] I have read the [CONTRIBUTING.md](../CONTRIBUTING.md) guidelines
- [ ] I have read the [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)
- [ ] My code/rules follow the project style guidelines
- [ ] I have performed a self-review of my changes
- [ ] I have commented my code/rules where necessary
- [ ] I have updated documentation as needed
- [ ] My changes generate no new warnings or errors
- [ ] I have tested my changes thoroughly
- [ ] All existing tests still pass
- [ ] I have checked for conflicts with the base branch

---

## Additional Context

<!-- Any additional information that reviewers should know -->


---

## Reviewer Notes

<!-- For maintainers: Add review comments, testing results, or deployment notes -->
