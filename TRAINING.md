## Training Session Checklist

### Pre-Session Setup
- [ ] Clone repository to isolated environment
- [ ] Verify Go 1.19+ is installed
- [ ] Test application starts: `./run.sh`
- [ ] Confirm Docker is available (if using containers)
- [ ] Set up Checkmarx One project
- [ ] Prepare network isolation

### Scanning Workflow

#### 1. Initial SAST Scan
- [ ] Run Checkmarx One SAST scan
- [ ] Identify SQL injection vulnerabilities
- [ ] Locate XSS issues in templates
- [ ] Find hard-coded credentials
- [ ] Review code quality issues

**Expected Results**: 4-6 high-severity SAST findings

#### 2. SCA Vulnerability Assessment
- [ ] Execute SCA scan on dependencies
- [ ] Identify vulnerable JWT library (CVE-2020-26160)
- [ ] Review dependency tree analysis
- [ ] Check for license compliance issues

**Expected Results**: 1 critical SCA vulnerability

#### 3. IaC Security Review
- [ ] Scan Dockerfile for misconfigurations
- [ ] Review Kubernetes manifests
- [ ] Identify privilege escalation risks
- [ ] Check for hardcoded secrets

**Expected Results**: 3-5 IaC security issues

#### 4. API Security Assessment
- [ ] Import swagger.yaml to Checkmarx One
- [ ] Run API security scan
- [ ] Test authentication bypass
- [ ] Verify endpoint inventory discovery

**Expected Results**: 2-3 documented API issues, discovery of shadow APIs

#### 5. DAST Testing
- [ ] Start application: `./run.sh`
- [ ] Configure DAST scan target (localhost:8080)
- [ ] Run dynamic security tests
- [ ] Test vulnerable endpoints manually

**Expected Results**: Missing security headers, IDOR vulnerabilities

### Remediation Training

#### For Each Vulnerability:
- [ ] Review finding in Checkmarx One
- [ ] Open corresponding remediation guide
- [ ] Study vulnerable code example
- [ ] Implement secure alternative
- [ ] Re-scan to verify fix
- [ ] Document learning outcomes

#### Priority Order:
1. **Critical**: SQL Injection (main.go:searchHandler)
2. **High**: JWT Vulnerability (dependency upgrade)
3. **High**: XSS in templates (proper escaping)
4. **Medium**: Docker security (user context)
5. **Medium**: API authentication (proper validation)
6. **Low**: Missing security headers

### Advanced Training Scenarios

#### Shadow API Discovery
- [ ] Compare documented APIs (swagger.yaml) vs running application
- [ ] Use API inventory tools to find undocumented endpoints
- [ ] Test `/api/v1/internal/*` endpoints
- [ ] Document security implications

#### Dependency Confusion
- [ ] Review go.mod for private/public packages
- [ ] Understand supply chain risks
- [ ] Practice secure dependency management

#### Container Security
- [ ] Build Docker image: `docker build -t vulnerable-app .`
- [ ] Scan image for vulnerabilities
- [ ] Review runtime security settings
- [ ] Implement security best practices

### Post-Session Review
- [ ] Export scan results from Checkmarx One
- [ ] Compare before/after vulnerability counts
- [ ] Document lessons learned
- [ ] Clean up training environment
- [ ] Archive scan reports

### Troubleshooting

#### Application Won't Start
1. Check Go version: `go version`
2. Verify dependencies: `go mod download`
3. Review error logs in terminal
4. Ensure SQLite is available

#### Checkmarx One Issues
1. Verify project configuration
2. Check source code upload
3. Review scan settings
4. Confirm license availability

#### Docker Problems
1. Test Docker daemon: `docker ps`
2. Review Dockerfile syntax
3. Check build context
4. Verify base image availability

### Expected Learning Outcomes

After completion, participants should understand:
- How to identify and fix SQL injection vulnerabilities
- Secure coding practices for web applications
- Dependency management and SCA scanning
- Infrastructure security configuration
- API security testing methodologies
- Integration of security into CI/CD pipelines

### Additional Resources
- Remediation guides in `/remediation/` directory
- OWASP Top 10 documentation
- Checkmarx One user guides
- Secure coding standards