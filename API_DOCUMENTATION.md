# API Documentation and Inventory Discovery

This directory contains Swagger/OpenAPI documentation that intentionally demonstrates API inventory and documentation issues commonly found by Checkmarx One API scanning.

## Files

- `swagger.yaml` - OpenAPI 3.0 specification with intentional gaps
- `swagger.json` - JSON version of the API specification (if needed)

## API Inventory Issues Demonstrated

### 1. **Undocumented Shadow APIs**
The application implements several "shadow" APIs that are NOT documented in the Swagger specification:

#### Undocumented Endpoints:
- `GET /api/v1/internal/debug` - Debug information endpoint
- `POST /api/v1/internal/backup` - Database backup endpoint  
- `GET /api/v1/internal/logs` - Application logs endpoint

These endpoints represent **API inventory discrepancies** that Checkmarx One can detect by:
- Scanning the actual codebase for API routes
- Comparing implemented endpoints with documented APIs
- Identifying shadow/undocumented APIs that pose security risks

### 2. **Documented vs Implemented Differences**
The Swagger documentation is intentionally incomplete to demonstrate how API inventory discovery works:

#### Missing from Documentation:
- Internal debug endpoints (`/api/v1/internal/*`)
- Some web interface endpoints (`/search`, `/comments`)
- Additional query parameters and headers used by the application

### 3. **Security Issues in API Documentation**
The Swagger file includes security annotations highlighting vulnerabilities:

- **Authentication bypasses** - Some endpoints marked as `security: []`
- **IDOR vulnerabilities** - Path parameters without proper validation
- **Data exposure** - Schemas showing sensitive fields that shouldn't be exposed
- **Weak authentication** - Hardcoded API keys and weak JWT patterns

## Testing with Checkmarx One

### API Security Scanning
Checkmarx One can analyze this application to:

1. **Discover API Inventory**
   - Scan Go code to find all route definitions
   - Compare with Swagger documentation
   - Identify undocumented endpoints

2. **Validate API Security**
   - Check for OWASP API Top 10 vulnerabilities
   - Analyze authentication and authorization patterns
   - Identify data exposure risks

3. **Documentation Compliance**
   - Verify API documentation completeness
   - Check for security annotations
   - Validate schema definitions

### Expected Findings

When scanning this application, Checkmarx One should detect:

#### API Inventory Issues:
- ✅ Undocumented endpoint: `GET /api/v1/internal/debug`
- ✅ Undocumented endpoint: `POST /api/v1/internal/backup`  
- ✅ Undocumented endpoint: `GET /api/v1/internal/logs`
- ✅ Missing documentation for web endpoints

#### API Security Issues:
- ✅ **API1 - Broken Object Level Authorization**: IDOR in `/users/{id}`
- ✅ **API2 - Broken User Authentication**: Weak JWT implementation
- ✅ **API3 - Excessive Data Exposure**: Password/API keys in responses
- ✅ **API5 - Broken Function Level Authorization**: Missing access controls
- ✅ **API7 - Security Misconfiguration**: No rate limiting, weak auth
- ✅ **API8 - Injection**: SQL injection vulnerabilities
- ✅ **API10 - Insufficient Logging**: Poor security logging

## How to Use

### 1. Scan with Checkmarx One
```bash
# Upload the repository to Checkmarx One
# Enable API Security scanning
# Point to swagger.yaml for API documentation
```

### 2. Compare Results
Review scan results to see:
- Which undocumented APIs were discovered
- How API documentation gaps are identified
- Security vulnerabilities in documented vs undocumented endpoints

### 3. Review API Inventory
Check the API inventory report to see:
- Complete list of discovered endpoints
- Documentation coverage percentage
- Risk assessment for undocumented APIs

## Real-World Implications

### Security Risks of Undocumented APIs:
1. **Shadow IT** - APIs unknown to security teams
2. **Uncontrolled Access** - No security reviews or controls
3. **Data Leakage** - Sensitive information in debug endpoints
4. **Attack Surface** - Additional entry points for attackers
5. **Compliance Issues** - Untracked APIs in regulated environments

### Best Practices:
1. **Complete Documentation** - Document ALL APIs, including internal ones
2. **API Gateway** - Route all APIs through controlled gateways
3. **Regular Inventory** - Automated discovery of all endpoints
4. **Security Review** - All APIs should undergo security assessment
5. **Access Controls** - Proper authentication for all endpoints

## Remediation

To fix the API inventory issues:

1. **Document all endpoints** in Swagger/OpenAPI
2. **Remove or secure** debug/internal endpoints
3. **Implement proper authentication** on all APIs
4. **Add security annotations** to API documentation
5. **Regular API inventory audits** using automated tools

## Training Value

This setup demonstrates:
- How API documentation gaps create security risks
- The importance of complete API inventory management
- How security scanning tools discover undocumented APIs
- Real-world API security vulnerabilities
- The relationship between documentation and security

Perfect for training security teams on:
- API security assessment
- Documentation importance
- Shadow API risks
- Checkmarx One API scanning capabilities