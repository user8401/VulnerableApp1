# Vulnerable Web Application - Checkmarx One Training 

[![Security Scan](https://img.shields.io/badge/security-intentionally%20vulnerable-red.svg)](./SECURITY.md)
[![Go Version](https://img.shields.io/badge/go-1.19+-blue.svg)](https://golang.org/)
[![Training Ready](https://img.shields.io/badge/training-ready-green.svg)](./TRAINING.md)

This is a deliberately vulnerable web application built with Go and SQLite for Checkmarx One security testing and training purposes.

## ⚠️ Security Warning

**This application contains intentional security vulnerabilities for training purposes.**

- **DO NOT** deploy to production environments
- **DO NOT** connect to public networks  
- **DO NOT** use real credentials or sensitive data
- **USE ONLY** in isolated training environments

## Overview

This Go-based web application demonstrates common security vulnerabilities that can be detected and remediated using Checkmarx One security scanning tools. It serves as a comprehensive training platform for learning about:

- **SAST** (Static Application Security Testing)
- **SCA** (Software Composition Analysis)  
- **IaC** (Infrastructure as Code) Security
- **API Security** Testing
- **DAST** (Dynamic Application Security Testing)

## Quick Start

### Prerequisites
- Go 1.19 or later
- SQLite3
- Git
- Docker (optional)
- Kubernetes (optional)

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd VulnerableApp

# Install dependencies
go mod download

# Start the application
./run.sh

# Access the application
open http://localhost:8080
```

## Vulnerability Catalog

### SAST Vulnerabilities

| Vulnerability | Location | Severity | CWE |
|---------------|----------|----------|-----|
| SQL Injection | `main.go:searchHandler` | Critical | CWE-89 |
| SQL Injection | `main.go:loginHandler` | Critical | CWE-89 |
| Cross-Site Scripting | `templates/search.html` | High | CWE-79 |
| Hard-coded Secrets | `main.go:initDB` | Medium | CWE-798 |

### SCA Vulnerabilities

| Package | Version | CVE | Severity | Fix Available |
|---------|---------|-----|----------|---------------|
| github.com/dgrijalva/jwt-go | v3.2.0 | CVE-2020-26160 | High | ✅ Yes |

### IaC Security Issues

| File | Issue | Severity | Description |
|------|-------|----------|-------------|
| `Dockerfile` | Root User | High | Container runs as root |
| `Dockerfile` | Hardcoded Secrets | Medium | Environment variables exposed |
| `k8s-deployment.yaml` | Privileged Container | Critical | Security context allows privilege escalation |

### API Security Vulnerabilities

| Endpoint | Vulnerability | OWASP API Category |
|----------|---------------|-------------------|
| `/api/login` | Broken Authentication | API1:2023 |
| `/api/search` | Excessive Data Exposure | API3:2023 |
| `/api/v1/internal/*` | Improper Inventory Management | API9:2023 |

### DAST Issues

- Missing security headers (HSTS, CSP, X-Frame-Options)
- Insecure Direct Object References (IDOR)
- Information disclosure in error messages
- Session management vulnerabilities

## Architecture

```
VulnerableApp/
├── main.go                 # Main application (contains vulnerabilities)
├── go.mod                  # Dependencies (includes vulnerable packages)
├── run.sh                  # Application startup script
├── templates/              # HTML templates (XSS vulnerabilities)
├── static/                 # CSS and static assets
├── remediation/            # Security fix documentation
├── swagger.yaml            # API documentation (intentionally incomplete)
├── Dockerfile              # Container configuration (misconfigurations)
├── k8s-deployment.yaml     # Kubernetes manifest (security issues)
└── docs/                   # Additional documentation
```

## Training Workflow

### 1. Initial Scan Setup
```bash
# Set up Checkmarx One project
# Configure source code repository
# Initiate baseline security scan
```

### 2. Vulnerability Discovery
- Run SAST scan to identify code vulnerabilities
- Execute SCA scan for dependency issues  
- Perform IaC scan on Docker/Kubernetes files
- Test API security with swagger documentation
- Conduct DAST scan on running application

### 3. Remediation Practice
- Follow guides in `/remediation/` directory
- Implement secure coding fixes
- Upgrade vulnerable dependencies
- Secure infrastructure configurations
- Re-scan to verify fixes

See [TRAINING.md](./TRAINING.md) for detailed session checklist.

## API Documentation

The application includes both documented and undocumented APIs:

### Documented APIs (swagger.yaml)
- `POST /api/login` - User authentication
- `GET /api/search` - Content search
- `GET /api/users/{id}` - User profile retrieval

### Shadow APIs (Undocumented)
These endpoints exist in the application but are intentionally omitted from swagger.yaml to demonstrate API inventory discovery:

- `GET /api/v1/internal/debug` - Debug information
- `POST /api/v1/internal/backup` - Database backup
- `GET /api/v1/internal/logs` - Application logs

## Development Setup

### Running with Docker
```bash
# Build container
docker build -t vulnerable-app .

# Run container (insecurely configured)
docker run -p 8080:8080 vulnerable-app
```

### Kubernetes Deployment
```bash
# Deploy to cluster (with security misconfigurations)
kubectl apply -f k8s-deployment.yaml

# Access via port-forward
kubectl port-forward deployment/vulnerable-app 8080:8080
```

## Testing Vulnerabilities

### SQL Injection Test
```bash
# Test login bypass
curl -X POST http://localhost:8080/api/login \
  -d "username=admin' OR '1'='1&password=anything"

# Test search injection  
curl "http://localhost:8080/search?q='; DROP TABLE users; --"
```

### XSS Test
```bash
# Submit malicious script
curl -X POST http://localhost:8080/search \
  -d "query=<script>alert('XSS')</script>"
```

### JWT Vulnerability Test
```bash
# Test signature bypass (CVE-2020-26160)
# Generate token with 'none' algorithm
```

## Remediation Resources

Each vulnerability includes comprehensive remediation guidance:

- **[SAST Fixes](./remediation/sast-remediation.md)** - Secure coding practices
- **[SCA Fixes](./remediation/sca-remediation.md)** - Dependency management  
- **[IaC Fixes](./remediation/iac-remediation.md)** - Infrastructure security
- **[API Security](./remediation/api-remediation.md)** - API protection strategies

## Contributing

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on:
- Making training content updates
- Adding new vulnerability examples
- Maintaining educational value
- Testing with security scanners

## Security Policy

See [SECURITY.md](./SECURITY.md) for:
- Vulnerability disclosure process
- Training vs. real security issues
- Contact information
- Supported versions

## License

This project is for educational purposes only. See [LICENSE](./LICENSE) for details.

## Support

- **Training Questions**: training@checkmarx.com
- **Technical Issues**: Create an issue in this repository
- **Checkmarx One Help**: Refer to official documentation

---

**Remember**: This application is intentionally vulnerable. Use only for security training in isolated environments.
