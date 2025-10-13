# Docker Security Remediation

## Problem Description

The current Docker configuration contains multiple security vulnerabilities including running as root, using outdated base images, hardcoded secrets, and excessive permissions.

## Current Vulnerable Dockerfile Issues

1. **Outdated base image** - Ubuntu 18.04 with known vulnerabilities
2. **Running as root** - Default root user throughout
3. **Hardcoded secrets** - Passwords and keys in build arguments
4. **Excessive permissions** - chmod 777 on directories
5. **Unnecessary packages** - Installing tools not needed for runtime
6. **No multi-stage build** - Exposing build tools and source code
7. **Missing security scanning** - No vulnerability scans during build

## Secure Dockerfile

```dockerfile
# SECURE: Multi-stage build with security best practices

# Build stage
FROM golang:1.21-alpine AS builder

# Security: Install security updates and minimal packages
RUN apk update && apk add --no-cache \
    ca-certificates \
    git \
    && rm -rf /var/cache/apk/*

# Security: Create non-root user for build
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Security: Copy only what's needed
COPY go.mod go.sum ./

# Download dependencies (cached layer)
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Security: Build with security flags
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o vulnerable-app main.go

# Security: Verify the binary
RUN file vulnerable-app

# Runtime stage - minimal image
FROM alpine:3.18

# Security: Install only runtime dependencies and security updates
RUN apk update && apk add --no-cache \
    ca-certificates \
    sqlite \
    tzdata \
    && rm -rf /var/cache/apk/* \
    && update-ca-certificates

# Security: Create non-root user
RUN addgroup -g 1001 appgroup && \
    adduser -D -s /bin/sh -u 1001 -G appgroup appuser

# Security: Create app directory with proper permissions
RUN mkdir -p /app && \
    chown -R appuser:appgroup /app

# Set working directory
WORKDIR /app

# Security: Copy binary from builder stage
COPY --from=builder /build/vulnerable-app .
COPY --from=builder /build/templates ./templates
COPY --from=builder /build/static ./static

# Security: Set proper file permissions
RUN chmod 755 vulnerable-app && \
    chown -R appuser:appgroup /app

# Security: Switch to non-root user
USER appuser

# Security: Expose only necessary port
EXPOSE 8080

# Security: Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Security: Use proper entrypoint
ENTRYPOINT ["./vulnerable-app"]

# Security: Set metadata
LABEL maintainer="security@example.com" \
      version="1.0" \
      description="Vulnerable Web App for Training"
```

## Secure Docker Compose

```yaml
# SECURE: docker-compose.yml with security best practices
version: '3.8'

services:
  vulnerable-app:
    build: 
      context: .
      dockerfile: Dockerfile
    ports:
      # Security: Only expose necessary port
      - "8080:8080"
    environment:
      # Security: Use secrets instead of hardcoded values
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - API_KEY_FILE=/run/secrets/api_key
    secrets:
      - db_password
      - api_key
    volumes:
      # Security: Read-only application data
      - app_data:/app/data:ro
    networks:
      - app_network
    # Security: Resource limits
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    # Security: Restart policy
    restart: unless-stopped
    # Security: Health check
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    # Security: Security options
    security_opt:
      - no-new-privileges:true
    # Security: Read-only root filesystem
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    # Security: Drop all capabilities
    cap_drop:
      - ALL
    # Security: Run as non-root
    user: "1001:1001"

networks:
  app_network:
    driver: bridge
    # Security: Custom network configuration
    driver_opts:
      com.docker.network.bridge.enable_icc: "false"
      com.docker.network.bridge.enable_ip_masquerade: "true"
      com.docker.network.bridge.host_binding_ipv4: "127.0.0.1"

volumes:
  app_data:
    driver: local

secrets:
  db_password:
    file: ./secrets/db_password.txt
  api_key:
    file: ./secrets/api_key.txt
```

## Secure Secrets Management

### Create Secrets Directory
```bash
# Create secrets directory (not in version control)
mkdir -p secrets
echo "supersecret123" > secrets/db_password.txt
echo "admin-secret-key" > secrets/api_key.txt
chmod 600 secrets/*.txt
```

### Update .gitignore
```gitignore
# Secrets
secrets/
*.key
*.pem
*.p12
.env
.env.*
```

### Application Code for Secrets
```go
// Secure secret reading from files
func readSecret(secretPath string) (string, error) {
    if secretPath == "" {
        return "", errors.New("secret path not provided")
    }
    
    data, err := ioutil.ReadFile(secretPath)
    if err != nil {
        return "", fmt.Errorf("failed to read secret: %v", err)
    }
    
    return strings.TrimSpace(string(data)), nil
}

// Update main function to read secrets
func main() {
    // Read secrets from files (Docker secrets)
    dbPasswordFile := os.Getenv("DB_PASSWORD_FILE")
    apiKeyFile := os.Getenv("API_KEY_FILE")
    
    var dbPassword, apiKey string
    var err error
    
    if dbPasswordFile != "" {
        dbPassword, err = readSecret(dbPasswordFile)
        if err != nil {
            log.Fatal("Failed to read database password:", err)
        }
    }
    
    if apiKeyFile != "" {
        apiKey, err = readSecret(apiKeyFile)
        if err != nil {
            log.Fatal("Failed to read API key:", err)
        }
    }
    
    // Use secrets in application
    initDB(dbPassword)
    initSessions(apiKey)
    
    // Rest of application...
}
```

## Docker Security Scanning

### Dockerfile for Security Scanning
```dockerfile
# Add security scanning to build process
FROM golang:1.21-alpine AS security-scanner

# Install security scanning tools
RUN apk add --no-cache \
    trivy \
    grype

# Copy source for scanning
COPY . /src
WORKDIR /src

# Run security scans
RUN trivy fs --exit-code 1 --no-progress /src
RUN grype /src --fail-on medium

# Continue with secure build...
FROM golang:1.21-alpine AS builder
# ... rest of secure build
```

### CI/CD Pipeline Security
```yaml
# .github/workflows/docker-security.yml
name: Docker Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  docker-security:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: Build Docker image
      run: docker build -t vulnerable-app:test .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'vulnerable-app:test'
        format: 'sarif'
        output: 'trivy-results.sarif'
        exit-code: 1
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: 'trivy-results.sarif'
    
    - name: Run Hadolint Dockerfile linter
      uses: hadolint/hadolint-action@v3.1.0
      with:
        dockerfile: Dockerfile
        failure-threshold: error
    
    - name: Run Docker Bench Security
      run: |
        docker run --rm --net host --pid host --userns host --cap-add audit_control \
          -v /etc:/etc:ro \
          -v /var/lib:/var/lib:ro \
          -v /var/run/docker.sock:/var/run/docker.sock:ro \
          --label docker_bench_security \
          docker/docker-bench-security
```

## Container Runtime Security

### Docker Daemon Configuration
```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "userland-proxy": false,
  "live-restore": true,
  "no-new-privileges": true,
  "seccomp-profile": "/etc/docker/seccomp/default.json",
  "apparmor-profile": "docker-default"
}
```

### Runtime Security Options
```bash
# Run with enhanced security
docker run -d \
  --name vulnerable-app \
  --security-opt=no-new-privileges:true \
  --security-opt=apparmor:docker-default \
  --security-opt=seccomp:default.json \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=100m \
  --user 1001:1001 \
  -p 127.0.0.1:8080:8080 \
  vulnerable-app:latest
```

## Implementation Steps

### Step 1: Create Secure Dockerfile
1. Replace current Dockerfile with secure version
2. Implement multi-stage build
3. Add security scanning steps
4. Test build process

### Step 2: Update Docker Compose
1. Replace current docker-compose.yml
2. Add secrets management
3. Configure security options
4. Test deployment

### Step 3: Set Up Security Scanning
1. Add Trivy scanner to CI/CD
2. Configure Hadolint for Dockerfile linting
3. Set up Docker Bench Security
4. Configure security gates

### Step 4: Update Application Code
1. Add secret file reading functionality
2. Update environment variable handling
3. Add proper error handling
4. Test with new configuration

## Testing Docker Security

### Security Scan Script
```bash
#!/bin/bash
# scripts/docker-security-scan.sh

echo "🔒 Running Docker Security Scan..."

# Build image
echo "Building image..."
docker build -t vulnerable-app:security-test .

# Run Trivy scan
echo "Running Trivy vulnerability scan..."
trivy image --exit-code 1 vulnerable-app:security-test

# Run Hadolint
echo "Running Hadolint Dockerfile analysis..."
hadolint Dockerfile

# Run container structure test
echo "Running container structure tests..."
container-structure-test test --image vulnerable-app:security-test --config container-test.yaml

# Run Docker Bench
echo "Running Docker Bench Security..."
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security

echo "✅ Docker security scan complete"
```

### Container Structure Test
```yaml
# container-test.yaml
schemaVersion: '2.0.0'

metadataTest:
  exposedPorts: ["8080"]
  user: "1001"
  workdir: "/app"

commandTests:
  - name: "Check application binary exists"
    command: "ls"
    args: ["/app/vulnerable-app"]
    expectedOutput: ["/app/vulnerable-app"]

fileExistenceTests:
  - name: "Check application binary"
    path: "/app/vulnerable-app"
    shouldExist: true
    permissions: "-rwxr-xr-x"
    uid: 1001
    gid: 1001

licenseTests:
  - debian: false
    files: []
```

## Security Best Practices

### Image Security
1. **Use minimal base images** - Alpine or distroless
2. **Multi-stage builds** - Separate build and runtime
3. **Regular updates** - Keep base images current
4. **Vulnerability scanning** - Scan images before deployment
5. **Image signing** - Use Docker Content Trust

### Runtime Security
1. **Non-root user** - Never run as root
2. **Read-only filesystem** - Mount root as read-only
3. **Drop capabilities** - Remove unnecessary privileges
4. **Resource limits** - Prevent resource exhaustion
5. **Network segmentation** - Use custom networks

### Secrets Management
1. **External secrets** - Use Docker secrets or external vaults
2. **No hardcoded secrets** - Never embed in images
3. **Proper permissions** - Restrict secret file access
4. **Rotation** - Regularly rotate secrets

## Tools for Docker Security

### Scanning Tools
- **Trivy** - Comprehensive vulnerability scanner
- **Grype** - Container vulnerability scanner
- **Clair** - Static analysis for containers
- **Twistlock/Prisma** - Commercial container security

### Linting Tools
- **Hadolint** - Dockerfile linter
- **Container Structure Test** - Validates container structure
- **Docker Bench Security** - CIS benchmark compliance

### Runtime Security
- **Falco** - Runtime security monitoring
- **Sysdig** - Container monitoring and security
- **Aqua Security** - Container security platform

## Additional Resources

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)