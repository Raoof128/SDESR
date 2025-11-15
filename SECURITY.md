# Security Policy

## Reporting a Vulnerability

The security of this SIEM detection engineering portfolio is important. If you discover a security vulnerability in the detection rules, scripts, or configurations, please report it responsibly.

### Reporting Process

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities via:

1. **GitHub Security Advisories** (Preferred)
   - Navigate to the "Security" tab
   - Click "Report a vulnerability"
   - Provide detailed information

2. **Email Report**
   - Send to: [your.email@example.com]
   - Subject: "SECURITY: [Brief Description]"
   - Include detailed reproduction steps

### What to Include in Your Report

Please include the following information:

- **Type of vulnerability** (detection bypass, script vulnerability, configuration weakness)
- **Affected component** (specific Sigma rule, Python script, Docker configuration)
- **Attack scenario** that demonstrates the vulnerability
- **Potential impact** (bypass detection, code execution, information disclosure)
- **Suggested fix** (if available)
- **Steps to reproduce** with sample commands or logs

### Example Security Issues

Examples of security issues worth reporting:

- **Detection Bypass:** Malicious activity that evades existing detection rules
- **Script Vulnerabilities:** Code injection, path traversal, or unsafe file operations in Python scripts
- **Container Security:** Unsafe Docker configurations or exposed credentials
- **False Negative:** Critical attacks not detected by rules (e.g., Mimikatz variant bypassing detection)
- **Information Disclosure:** Sensitive data exposure in logs or configurations

### Response Timeline

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Timeline:** Depends on severity
  - Critical: 1-7 days
  - High: 7-14 days
  - Medium: 14-30 days
  - Low: 30+ days

### Disclosure Policy

- **Coordinated Disclosure:** We follow responsible disclosure practices
- **Public Disclosure:** After fix is released and tested (typically 30-90 days)
- **Credit:** Security researchers will be credited unless they prefer anonymity

### Security Best Practices

When using this portfolio:

1. **Rule Tuning Required**
   - All detection rules should be tuned for your environment
   - Test in a non-production SIEM first
   - Monitor false positive rates during initial deployment

2. **Credential Management**
   - Never commit credentials to version control
   - Use environment variables or secret managers
   - Rotate default lab credentials immediately

3. **Lab Environment Security**
   - Lab Docker containers are for testing only
   - Do not expose lab SIEM instances to the internet
   - Use network segmentation and firewalls
   - Default credentials (admin/Changeme123!) are intentionally weak - change them

4. **Script Execution**
   - Review all Python scripts before execution
   - Run scripts in isolated environments
   - Validate input when modifying scripts
   - Use virtual environments for dependency isolation

5. **Sigma Rule Security**
   - Validate all rules before SIEM deployment
   - Review detection logic for unintended matches
   - Test rules against benign baseline traffic
   - Monitor for evasion techniques

### Known Limitations

This portfolio is designed for **detection engineering demonstration** and **educational purposes**:

- **Not Production-Hardened:** Additional tuning required for enterprise deployment
- **Lab Environment:** Docker configuration is not production-ready
- **Detection Coverage:** Rules cover common techniques but not all attack variants
- **False Positives:** Baseline tuning required for each environment

### Security Features

Security measures implemented in this portfolio:

- **Input Validation:** Python scripts validate Sigma YAML syntax
- **.gitignore:** Prevents committing secrets and credentials
- **Dependency Pinning:** requirements.txt specifies minimum versions
- **UUID Validation:** Ensures all Sigma rules have valid identifiers
- **Read-Only Operations:** Conversion scripts do not modify source rules

### Vulnerability Disclosure History

No vulnerabilities have been reported to date.

---

## Out of Scope

The following are considered **out of scope** for security reports:

- Theoretical attacks without proof-of-concept
- Detection rule false positives (report via GitHub Issues instead)
- Social engineering attacks
- Denial-of-service against lab environment
- Issues in third-party dependencies (report to upstream projects)

---

## Contact

For non-security issues, please use:
- **Bug Reports:** GitHub Issues with "bug" label
- **False Positives:** GitHub Issues with "false-positive" label
- **Feature Requests:** GitHub Issues with "enhancement" label

---

**Last Updated:** November 2025
**Policy Version:** 1.0
