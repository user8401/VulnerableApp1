# Vulnerable Web Application

This is a deliberately vulnerable web application built with Go and SQLite for security testing and training purposes.

## ⚠️ WARNING
This application contains intentional security vulnerabilities. **DO NOT** deploy this in a production environment or any system connected to the internet without proper isolation.

## Features and Vulnerabilities

### SAST (Static Application Security Testing) Issues:

1. **SQL Injection Vulnerabilities**
   - Login form: `POST /login`
   - Search functionality: `GET /search?q=`
   - Vulnerable code in `searchHandler` and `loginHandler`

2. **Cross-Site Scripting (XSS)**
   - Comment system: `POST /comments`
   - Comments display without proper escaping
   - Reflected XSS in search results

### SCA (Software Composition Analysis) Issues:

3. **Vulnerable Dependencies**
   - `github.com/dgrijalva/jwt-go v3.2.0+incompatible` - Known vulnerability CVE-2020-26160
   - `gopkg.in/yaml.v2 v2.2.8` - Potential vulnerabilities in older version
   - Using Go 1.19 which may have known issues

### IaC (Infrastructure as Code) Security Issues:

4. **Docker Security Misconfigurations**
   - Running as root user
   - Using outdated base image (Ubuntu 18.04)
   - Hardcoded secrets in Dockerfile
   - Overly permissive file permissions
   - Exposing unnecessary ports

5. **Kubernetes Security Issues**
   - No security context defined
   - Running containers as root
   - Mounting sensitive host paths
   - No resource limits
   - Hardcoded secrets in manifests

### API Security Issues (OWASP API Top 10):

6. **API1: Broken Object Level Authorization**
   - `GET /api/v1/users/:id` - IDOR vulnerability
   - `PUT /api/v1/users/:id` - Can modify any user
   - `DELETE /api/v1/users/:id` - Can delete any user

7. **API2: Broken User Authentication**
   - Weak JWT implementation with hardcoded secret
   - No token expiration
   - `POST /api/v1/auth` - Weak authentication

8. **API3: Excessive Data Exposure**
   - `GET /api/v1/users` - Exposes passwords and API keys
   - `GET /api/v1/data` - Massive data exposure

9. **API5: Broken Function Level Authorization**
   - `GET /api/v1/admin/users` - Weak admin check
   - Most endpoints have no authorization

10. **API7: Security Misconfiguration**
    - Debug mode enabled in production
    - Verbose error messages
    - No rate limiting

### DAST (Dynamic Application Security Testing) Issues:

11. **Session Management**
    - Weak session secret
    - No session timeout
    - Insecure cookie settings

12. **Information Disclosure**
    - Debug mode exposing stack traces
    - Verbose error messages
    - API endpoints discoverable

13. **Missing Security Headers**
    - No CSRF protection
    - No XSS protection headers
    - No content security policy

## Running the Application

### Prerequisites
- Go 1.19 or later
- SQLite3

### Local Development
```bash
go mod download
go run main.go
```

### Using Docker
```bash
docker build -t vulnerable-app .
docker run -p 8080:8080 vulnerable-app
```

### Using Docker Compose
```bash
docker-compose up
```

### Using Kubernetes
```bash
kubectl apply -f k8s-deployment.yaml
```

## Testing the Vulnerabilities

### SQL Injection Testing
1. Navigate to `/search`
2. Try payloads like:
   - `' OR '1'='1`
   - `' UNION SELECT 1,username,password FROM users--`

### XSS Testing
1. Navigate to `/comments`
2. Add comments with payloads like:
   - `<script>alert('XSS')</script>`
   - `<img src=x onerror=alert('XSS')>`

### API Testing
1. Test unauthorized access:
   - `curl http://localhost:8080/api/v1/users`
   - `curl http://localhost:8080/api/v1/users/1`

2. Test IDOR:
   - `curl -X PUT http://localhost:8080/api/v1/users/1 -d '{"role":"admin"}' -H "Content-Type: application/json"`

### Authentication Testing
- Default credentials: `admin / admin123`
- Try SQL injection in login form

## Security Scanning

This application is designed to be detected by various security tools:

- **SAST Tools**: SonarQube, CodeQL, Semgrep, Checkmarx
- **SCA Tools**: Snyk, OWASP Dependency Check, WhiteSource
- **IaC Scanners**: Checkov, Terrascan, Kube-score
- **DAST Tools**: OWASP ZAP, Burp Suite, Nuclei

## Educational Purpose

This application demonstrates common security vulnerabilities found in web applications. Use it to:

- Learn about different types of security vulnerabilities
- Practice using security scanning tools
- Understand how to identify and fix security issues
- Train development teams on secure coding practices

## License

This project is for educational purposes only. Use at your own risk.