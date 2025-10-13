# Contributing to the Vulnerable Web Application

## ⚠️ Important Security Notice

This application contains **intentional security vulnerabilities** for training purposes. Do not:
- Deploy to production environments
- Connect to public networks
- Use real credentials or sensitive data
- Submit security fixes (vulnerabilities are intentional)

## Getting Started

### Prerequisites
- Go 1.19 or later
- SQLite3
- Docker (optional)
- Kubernetes (optional)

### Setup
1. Clone the repository
2. Run `go mod download` to install dependencies
3. Execute `./run.sh` to start the application
4. Access at http://localhost:8080

## Development Guidelines

### Code Structure
- `main.go` - Main application with intentional vulnerabilities
- `templates/` - HTML templates (some with XSS vulnerabilities)
- `static/` - CSS and static assets
- `remediation/` - Security fix documentation
- `swagger.yaml` - API documentation (intentionally incomplete)

### Making Changes

#### For Training Content Updates:
1. Create a feature branch: `git checkout -b feature/update-training`
2. Make your changes
3. Test the application still runs
4. Commit with descriptive messages
5. Create a pull request

#### For Vulnerability Updates:
1. Ensure vulnerabilities remain detectable by security tools
2. Update corresponding remediation guides
3. Test with Checkmarx One to verify detection
4. Document new vulnerability types in README.md

### Branch Naming
- `feature/` - New features or training content
- `bugfix/` - Fixes to non-security issues
- `docs/` - Documentation updates
- `vulnerability/` - New vulnerability additions

### Commit Messages
Follow conventional commits format:
```
type(scope): description

Examples:
feat(api): add new vulnerable endpoint for IDOR training
docs(remediation): update SQL injection fix guide
vuln(auth): add JWT signature bypass vulnerability
```

### Testing
Before submitting changes:
1. Verify application starts: `./run.sh`
2. Test vulnerable endpoints work
3. Ensure documentation is accurate
4. Validate Docker build: `docker build -t vulnerable-app .`

## Security Training Focus

### Vulnerability Categories
This application demonstrates:
- **SAST**: SQL Injection, XSS, Code Quality
- **SCA**: Vulnerable dependencies (JWT library)
- **IaC**: Docker and Kubernetes misconfigurations
- **API Security**: OWASP API Top 10 vulnerabilities
- **DAST**: Runtime security issues

### Checkmarx One Integration
When making changes, ensure they:
- Remain detectable by CxOne scanning
- Include appropriate remediation guidance
- Demonstrate real-world security issues
- Provide educational value

## Documentation Standards

### Code Comments
- Mark vulnerabilities clearly: `// VULNERABLE: Description`
- Explain why code is insecure
- Reference OWASP categories where applicable

### Remediation Guides
- Include vulnerable and secure code examples
- Provide step-by-step fix instructions
- Reference security best practices
- Include testing procedures

## Review Process

### Pull Request Requirements
- [ ] Application builds and runs successfully
- [ ] Vulnerabilities remain detectable
- [ ] Documentation is updated
- [ ] No real security credentials
- [ ] Training value is clear

### Security Review
All changes must:
1. Maintain educational vulnerability examples
2. Not introduce unintended security risks
3. Include proper documentation
4. Be tested with security scanning tools

## Questions and Support

For questions about:
- **Training content**: Contact the security training team
- **Checkmarx One integration**: Refer to CxOne documentation
- **Technical issues**: Create an issue in the repository

## License

This project is for educational purposes only. See LICENSE file for details.