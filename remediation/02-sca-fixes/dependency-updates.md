# Dependency Updates and Vulnerability Management

## Problem Description

Software Composition Analysis (SCA) identifies security vulnerabilities in third-party dependencies. The vulnerable application uses several outdated libraries with known security issues.

## Current Vulnerable Dependencies

### 1. JWT Library - CVE-2020-26160
```go
// VULNERABLE
github.com/dgrijalva/jwt-go v3.2.0+incompatible
```
**Issue**: The library is susceptible to key confusion attacks where it accepts tokens signed with the "none" algorithm.

### 2. Potential Issues in Other Dependencies
```go
// May have vulnerabilities
gopkg.in/yaml.v2 v2.2.8  // Older version
github.com/gin-gonic/gin v1.8.1  // Check for latest
```

## Fixed Dependencies

### 1. Updated go.mod with Secure Dependencies

```go
module vulnerable-app

go 1.21  // Update to latest stable Go version

require (
    github.com/gin-gonic/gin v1.9.1          // Updated to latest
    github.com/mattn/go-sqlite3 v1.14.17     // Updated to latest
    github.com/golang-jwt/jwt/v5 v5.0.0      // Secure JWT library
    github.com/gorilla/sessions v1.2.1       // Updated
    golang.org/x/crypto v0.14.0              // For password hashing
    github.com/microcosm-cc/bluemonday v1.0.25 // For HTML sanitization
)

// Remove vulnerable dependencies
// github.com/dgrijalva/jwt-go - REMOVED
// gopkg.in/yaml.v2 v2.2.8 - REMOVED or updated to v3
```

### 2. Secure JWT Implementation

Replace the vulnerable JWT library with the secure version:

```go
// OLD VULNERABLE CODE:
import "github.com/dgrijalva/jwt-go"

// NEW SECURE CODE:
import "github.com/golang-jwt/jwt/v5"

// Secure JWT implementation
type Claims struct {
    UserID   int    `json:"user_id"`
    Username string `json:"username"`
    Role     string `json:"role"`
    jwt.RegisteredClaims
}

// Generate secure JWT token
func generateSecureJWT(userID int, username, role string) (string, error) {
    // Use a strong, random secret key (store in environment variable)
    secretKey := os.Getenv("JWT_SECRET_KEY")
    if secretKey == "" {
        return "", errors.New("JWT secret key not configured")
    }

    // Create claims with expiration
    claims := Claims{
        UserID:   userID,
        Username: username,
        Role:     role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // Short expiration
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            Issuer:    "vulnerable-app",
            Subject:   username,
            ID:        generateJTI(), // Unique token ID
        },
    }

    // Create token with claims
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    
    // Sign token with secret
    tokenString, err := token.SignedString([]byte(secretKey))
    if err != nil {
        return "", err
    }

    return tokenString, nil
}

// Validate JWT token
func validateJWT(tokenString string) (*Claims, error) {
    secretKey := os.Getenv("JWT_SECRET_KEY")
    if secretKey == "" {
        return nil, errors.New("JWT secret key not configured")
    }

    // Parse token
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        // Validate signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return []byte(secretKey), nil
    })

    if err != nil {
        return nil, err
    }

    // Validate claims
    if claims, ok := token.Claims.(*Claims); ok && token.Valid {
        return claims, nil
    }

    return nil, errors.New("invalid token")
}

// Generate unique token ID
func generateJTI() string {
    b := make([]byte, 16)
    rand.Read(b)
    return fmt.Sprintf("%x", b)
}

// SECURE: Updated auth handler
func authHandler(c *gin.Context) {
    username := c.PostForm("username")
    password := c.PostForm("password")

    // Validate input
    if err := validateInput(username, 50, "^[a-zA-Z0-9_]+$"); err != nil {
        c.JSON(400, gin.H{"error": "Invalid username"})
        return
    }

    var user User
    var hashedPassword string
    
    // Use parameterized query
    err := db.QueryRow("SELECT id, username, role, password FROM users WHERE username = ?",
        username).Scan(&user.ID, &user.Username, &user.Role, &hashedPassword)
    
    if err != nil {
        c.JSON(401, gin.H{"error": "Invalid credentials"})
        return
    }

    // Verify password
    if !checkPasswordHash(password, hashedPassword) {
        c.JSON(401, gin.H{"error": "Invalid credentials"})
        return
    }

    // Generate secure token
    token, err := generateSecureJWT(user.ID, user.Username, user.Role)
    if err != nil {
        log.Printf("JWT generation error: %v", err)
        c.JSON(500, gin.H{"error": "Internal server error"})
        return
    }

    c.JSON(200, gin.H{
        "token": token,
        "expires_in": 900, // 15 minutes
        "token_type": "Bearer",
    })
}
```

### 3. JWT Middleware for Authentication

```go
// JWT middleware for protected routes
func JWTMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(401, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }

        // Check Bearer token format
        tokenParts := strings.Split(authHeader, " ")
        if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
            c.JSON(401, gin.H{"error": "Invalid authorization header format"})
            c.Abort()
            return
        }

        // Validate token
        claims, err := validateJWT(tokenParts[1])
        if err != nil {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // Set user info in context
        c.Set("user_id", claims.UserID)
        c.Set("username", claims.Username)
        c.Set("role", claims.Role)
        
        c.Next()
    }
}
```

## Dependency Management Best Practices

### 1. Automated Dependency Scanning

Create `scripts/check-dependencies.sh`:
```bash
#!/bin/bash

echo "🔍 Checking for vulnerable dependencies..."

# Use Go's built-in vulnerability scanner (Go 1.18+)
echo "Running Go vulnerability scanner..."
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Use Nancy for additional scanning
echo "Running Nancy scanner..."
go list -json -deps ./... | nancy sleuth

# Use Snyk (if available)
if command -v snyk &> /dev/null; then
    echo "Running Snyk scanner..."
    snyk test --language=golang
fi

# Use OWASP Dependency Check
if command -v dependency-check &> /dev/null; then
    echo "Running OWASP Dependency Check..."
    dependency-check --project "VulnerableApp" --scan . --format ALL
fi

echo "✅ Dependency scan complete"
```

### 2. Dependency Update Automation

Create `.github/workflows/dependency-update.yml`:
```yaml
name: Dependency Updates

on:
  schedule:
    - cron: '0 0 * * 1'  # Weekly on Monday
  workflow_dispatch:

jobs:
  update-dependencies:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Update dependencies
      run: |
        go get -u ./...
        go mod tidy
    
    - name: Run vulnerability scan
      run: |
        go install golang.org/x/vuln/cmd/govulncheck@latest
        govulncheck ./...
    
    - name: Run tests
      run: go test ./...
    
    - name: Create PR
      uses: peter-evans/create-pull-request@v5
      with:
        token: ${{ secrets.GITHUB_TOKEN }}
        commit-message: 'chore: update dependencies'
        title: 'Automated dependency updates'
        body: 'This PR updates Go dependencies to their latest versions.'
```

### 3. Go.mod Security Configuration

```go
// go.mod with security-focused configuration
module vulnerable-app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/mattn/go-sqlite3 v1.14.17
    github.com/golang-jwt/jwt/v5 v5.0.0
    github.com/gorilla/sessions v1.2.1
    golang.org/x/crypto v0.14.0
    github.com/microcosm-cc/bluemonday v1.0.25
    golang.org/x/time v0.3.0 // For rate limiting
)

require (
    // Indirect dependencies will be listed here automatically
    // Keep them updated with 'go get -u ./...'
)

// Exclude known vulnerable versions
exclude (
    github.com/dgrijalva/jwt-go v3.2.0+incompatible
    gopkg.in/yaml.v2 v2.2.8
)

// Replace deprecated packages
replace github.com/dgrijalva/jwt-go => github.com/golang-jwt/jwt/v5 v5.0.0
```

## Implementation Steps

### Step 1: Update Dependencies
```bash
# Remove old dependencies
go mod edit -droprequire github.com/dgrijalva/jwt-go
go mod edit -droprequire gopkg.in/yaml.v2

# Add secure dependencies
go get github.com/golang-jwt/jwt/v5@latest
go get golang.org/x/crypto@latest
go get github.com/microcosm-cc/bluemonday@latest

# Update all dependencies
go get -u ./...
go mod tidy
```

### Step 2: Update Code
1. Replace all JWT-related code with secure implementation
2. Add proper error handling and validation
3. Implement JWT middleware for protected routes
4. Add environment variable management

### Step 3: Set Up Scanning
1. Install vulnerability scanners
2. Add CI/CD pipeline for dependency scanning
3. Set up automated dependency updates
4. Configure alerts for new vulnerabilities

### Step 4: Create Security Policy
Create `SECURITY.md`:
```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities to security@example.com

## Dependency Management

- Dependencies are scanned weekly for vulnerabilities
- Critical vulnerabilities are patched within 24 hours
- All dependencies are updated monthly
```

## Testing Dependency Fixes

### Automated Tests
```go
func TestJWTSecurity(t *testing.T) {
    // Test that none algorithm is rejected
    noneToken := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
        "user_id": 1,
        "exp":     time.Now().Add(time.Hour).Unix(),
    })
    
    tokenString, _ := noneToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
    
    _, err := validateJWT(tokenString)
    assert.Error(t, err, "Should reject none algorithm")
}

func TestTokenExpiration(t *testing.T) {
    // Create expired token
    claims := Claims{
        UserID: 1,
        Username: "test",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, _ := token.SignedString([]byte("test-secret"))
    
    _, err := validateJWT(tokenString)
    assert.Error(t, err, "Should reject expired token")
}
```

## Tools for SCA

### Go-Specific Tools
- **govulncheck** - Official Go vulnerability scanner
- **Nancy** - Vulnerability scanner for Go
- **Snyk** - Commercial vulnerability scanner

### General SCA Tools
- **OWASP Dependency Check** - Free, comprehensive scanner
- **WhiteSource/Mend** - Commercial solution
- **Sonatype Nexus** - Repository management with scanning

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Go Vulnerability Check
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...

- name: Snyk Security Scan
  uses: snyk/actions/golang@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
```

## Additional Resources

- [Go Vulnerability Database](https://vuln.go.dev/)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [Snyk Vulnerability Database](https://security.snyk.io/)