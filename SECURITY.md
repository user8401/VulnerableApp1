# Security Policy

## ⚠️ Important Notice

This repository contains **intentionally vulnerable code** for security training purposes. The vulnerabilities are deliberate and designed to be discovered by security scanning tools like Checkmarx One.

## Reporting Security Issues

### For Training-Related Issues
If you discover issues with the training content, remediation guides, or educational materials, please:

1. Open an issue in the repository with the label `training-content`
2. Describe the problem clearly
3. Suggest improvements if applicable

### For Real Security Vulnerabilities
If you discover unintended security vulnerabilities (not part of the training content):

1. **Do NOT open a public issue**
2. Email the security team directly at: security@checkmarx.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)

## Vulnerability Disclosure Timeline

For unintended vulnerabilities:
- **Day 0**: Report received and acknowledged
- **Day 7**: Initial assessment completed
- **Day 30**: Fix developed and tested
- **Day 45**: Fix deployed and disclosed publicly

## Training Vulnerabilities

### Intentional Vulnerabilities Include:

#### SAST (Static Application Security Testing)
- **SQL Injection** (CWE-89): Login and search endpoints
- **Cross-Site Scripting (XSS)** (CWE-79): User input display
- **Hard-coded Credentials** (CWE-798): Database connections
- **Weak Cryptography** (CWE-327): JWT implementation

#### SCA (Software Composition Analysis)
- **Vulnerable Dependencies**:
  - `github.com/dgrijalva/jwt-go v3.2.0` (CVE-2020-26160)
  - Known vulnerable JWT library

#### IaC (Infrastructure as Code)
- **Docker Security Issues**:
  - Running as root user
  - Hardcoded secrets in environment
  - Outdated base image (Ubuntu 18.04)
- **Kubernetes Misconfigurations**:
  - Privileged containers
  - Missing security contexts
  - Exposed sensitive ports

#### API Security (OWASP API Top 10)
- **Broken Authentication** (API1): Weak JWT validation
- **Excessive Data Exposure** (API3): Verbose error messages
- **Security Misconfiguration** (API7): Debug endpoints enabled
- **Improper Inventory Management** (API9): Undocumented endpoints

#### DAST (Dynamic Application Security Testing)
- **Missing Security Headers**: No CSRF protection
- **Insecure Direct Object References**: User data access
- **Information Disclosure**: Stack traces in responses

### Undocumented Endpoints (Shadow APIs)
These endpoints are intentionally not documented in swagger.yaml:
- `/api/v1/internal/debug` - Debug information exposure
- `/api/v1/internal/backup` - Data backup functionality
- `/api/v1/internal/logs` - Application log access

## Supported Versions

| Version | Supported | Purpose |
| ------- | --------- | ------- |
| main    | ✅ Current | Latest training content |
| dev     | ⚠️ Development | Unstable, testing only |

## Security Training Guidelines

### Do NOT:
- Deploy this application to production
- Connect to public networks
- Use real user credentials
- Store sensitive data
- Remove vulnerability warnings

### DO:
- Use in isolated training environments
- Follow remediation guides for learning
- Scan with Checkmarx One regularly
- Document new training scenarios
- Keep dependencies intentionally vulnerable

## Contact Information

- **Training Team**: training@checkmarx.com
- **Security Team**: security@checkmarx.com
- **Technical Support**: support@checkmarx.com

## License

This security training application is provided "as-is" for educational purposes only. No warranty or support is provided for production use.