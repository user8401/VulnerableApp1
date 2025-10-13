# API Authentication and Authorization Fixes

## Problem Description

The current API implementation has multiple security vulnerabilities related to authentication and authorization, including missing authentication, weak JWT implementation, and broken access controls.

## Current API Security Issues

1. **Missing Authentication** - Most endpoints have no authentication
2. **Weak JWT Implementation** - Using vulnerable library with weak secrets
3. **Broken Authorization** - No proper access control checks
4. **IDOR Vulnerabilities** - Users can access/modify other users' data
5. **Excessive Data Exposure** - APIs returning sensitive information
6. **No Rate Limiting** - APIs vulnerable to abuse

## Secure Authentication Implementation

### 1. Secure JWT Authentication

```go
package auth

import (
    "crypto/rand"
    "errors"
    "fmt"
    "os"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

// Secure JWT claims structure
type JWTClaims struct {
    UserID    int      `json:"user_id"`
    Username  string   `json:"username"`
    Role      string   `json:"role"`
    Scope     []string `json:"scope"`
    TokenType string   `json:"token_type"`
    jwt.RegisteredClaims
}

// Token pair for refresh token pattern
type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
}

// Secure authentication service
type AuthService struct {
    jwtSecret    []byte
    refreshSecret []byte
    issuer       string
}

func NewAuthService() (*AuthService, error) {
    jwtSecret := os.Getenv("JWT_SECRET")
    refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
    
    if jwtSecret == "" || refreshSecret == "" {
        return nil, errors.New("JWT secrets not configured")
    }
    
    return &AuthService{
        jwtSecret:     []byte(jwtSecret),
        refreshSecret: []byte(refreshSecret),
        issuer:        "vulnerable-app",
    }, nil
}

// Generate secure token pair
func (a *AuthService) GenerateTokenPair(userID int, username, role string) (*TokenPair, error) {
    // Generate unique token ID
    tokenID, err := a.generateTokenID()
    if err != nil {
        return nil, err
    }
    
    // Define user scopes based on role
    scopes := a.getUserScopes(role)
    
    // Create access token (short-lived)
    accessClaims := &JWTClaims{
        UserID:    userID,
        Username:  username,
        Role:      role,
        Scope:     scopes,
        TokenType: "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            Issuer:    a.issuer,
            Subject:   username,
            ID:        tokenID,
        },
    }
    
    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, err := accessToken.SignedString(a.jwtSecret)
    if err != nil {
        return nil, err
    }
    
    // Create refresh token (long-lived)
    refreshClaims := &JWTClaims{
        UserID:    userID,
        Username:  username,
        Role:      role,
        TokenType: "refresh",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 days
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            Issuer:    a.issuer,
            Subject:   username,
            ID:        tokenID + "_refresh",
        },
    }
    
    refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
    refreshTokenString, err := refreshToken.SignedString(a.refreshSecret)
    if err != nil {
        return nil, err
    }
    
    return &TokenPair{
        AccessToken:  accessTokenString,
        RefreshToken: refreshTokenString,
        TokenType:    "Bearer",
        ExpiresIn:    900, // 15 minutes
    }, nil
}

// Validate JWT token
func (a *AuthService) ValidateToken(tokenString string, tokenType string) (*JWTClaims, error) {
    var secret []byte
    if tokenType == "refresh" {
        secret = a.refreshSecret
    } else {
        secret = a.jwtSecret
    }
    
    token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Validate signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return secret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    claims, ok := token.Claims.(*JWTClaims)
    if !ok || !token.Valid {
        return nil, errors.New("invalid token")
    }
    
    // Validate token type
    if claims.TokenType != tokenType {
        return nil, errors.New("invalid token type")
    }
    
    return claims, nil
}

// Generate cryptographically secure token ID
func (a *AuthService) generateTokenID() (string, error) {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return fmt.Sprintf("%x", bytes), nil
}

// Get user scopes based on role
func (a *AuthService) getUserScopes(role string) []string {
    switch role {
    case "admin":
        return []string{"read", "write", "delete", "admin"}
    case "user":
        return []string{"read", "write"}
    default:
        return []string{"read"}
    }
}

// Refresh access token
func (a *AuthService) RefreshToken(refreshToken string) (*TokenPair, error) {
    claims, err := a.ValidateToken(refreshToken, "refresh")
    if err != nil {
        return nil, err
    }
    
    // Generate new token pair
    return a.GenerateTokenPair(claims.UserID, claims.Username, claims.Role)
}
```

### 2. Authentication Middleware

```go
package middleware

import (
    "net/http"
    "strings"
    
    "github.com/gin-gonic/gin"
)

// JWT Authentication middleware
func AuthMiddleware(authService *auth.AuthService) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Authorization header required",
                "code":  "MISSING_AUTH_HEADER",
            })
            c.Abort()
            return
        }
        
        // Parse Bearer token
        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || parts[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid authorization header format",
                "code":  "INVALID_AUTH_FORMAT",
            })
            c.Abort()
            return
        }
        
        // Validate token
        claims, err := authService.ValidateToken(parts[1], "access")
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid or expired token",
                "code":  "INVALID_TOKEN",
            })
            c.Abort()
            return
        }
        
        // Set user context
        c.Set("user_id", claims.UserID)
        c.Set("username", claims.Username)
        c.Set("role", claims.Role)
        c.Set("scopes", claims.Scope)
        c.Set("token_id", claims.ID)
        
        c.Next()
    }
}

// Role-based authorization middleware
func RequireRole(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        role, exists := c.Get("role")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Role information not found",
                "code":  "MISSING_ROLE",
            })
            c.Abort()
            return
        }
        
        userRole, ok := role.(string)
        if !ok {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Invalid role format",
                "code":  "INVALID_ROLE",
            })
            c.Abort()
            return
        }
        
        if !hasRequiredRole(userRole, requiredRole) {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Insufficient permissions",
                "code":  "INSUFFICIENT_PERMISSIONS",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// Scope-based authorization middleware
func RequireScope(requiredScope string) gin.HandlerFunc {
    return func(c *gin.Context) {
        scopes, exists := c.Get("scopes")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Scope information not found",
                "code":  "MISSING_SCOPE",
            })
            c.Abort()
            return
        }
        
        userScopes, ok := scopes.([]string)
        if !ok {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Invalid scope format",
                "code":  "INVALID_SCOPE",
            })
            c.Abort()
            return
        }
        
        if !hasRequiredScope(userScopes, requiredScope) {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Insufficient scope",
                "code":  "INSUFFICIENT_SCOPE",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// Check if user has required role
func hasRequiredRole(userRole, requiredRole string) bool {
    roleHierarchy := map[string]int{
        "guest": 0,
        "user":  1,
        "admin": 2,
    }
    
    userLevel, userExists := roleHierarchy[userRole]
    requiredLevel, requiredExists := roleHierarchy[requiredRole]
    
    return userExists && requiredExists && userLevel >= requiredLevel
}

// Check if user has required scope
func hasRequiredScope(userScopes []string, requiredScope string) bool {
    for _, scope := range userScopes {
        if scope == requiredScope {
            return true
        }
    }
    return false
}

// Resource ownership middleware (for IDOR protection)
func RequireOwnership(resourceParam string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userID, exists := c.Get("user_id")
        if !exists {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "User ID not found",
                "code":  "MISSING_USER_ID",
            })
            c.Abort()
            return
        }
        
        resourceID := c.Param(resourceParam)
        userIDInt, ok := userID.(int)
        if !ok {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Invalid user ID format",
                "code":  "INVALID_USER_ID",
            })
            c.Abort()
            return
        }
        
        // Convert resource ID to int for comparison
        resourceIDInt := 0
        if _, err := fmt.Sscanf(resourceID, "%d", &resourceIDInt); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{
                "error": "Invalid resource ID format",
                "code":  "INVALID_RESOURCE_ID",
            })
            c.Abort()
            return
        }
        
        // Check ownership (or admin override)
        role, _ := c.Get("role")
        if userIDInt != resourceIDInt && role != "admin" {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Access denied: resource not owned by user",
                "code":  "RESOURCE_NOT_OWNED",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

### 3. Secure API Handlers

```go
// Secure login handler
func (h *Handler) LoginHandler(c *gin.Context) {
    var loginReq struct {
        Username string `json:"username" binding:"required,max=50"`
        Password string `json:"password" binding:"required,max=100"`
    }
    
    if err := c.ShouldBindJSON(&loginReq); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid request format",
            "code":  "INVALID_REQUEST",
        })
        return
    }
    
    // Rate limiting check (implement with Redis or in-memory)
    if h.isRateLimited(c.ClientIP(), "login") {
        c.JSON(http.StatusTooManyRequests, gin.H{
            "error": "Too many login attempts",
            "code":  "RATE_LIMITED",
        })
        return
    }
    
    // Validate credentials
    user, err := h.validateCredentials(loginReq.Username, loginReq.Password)
    if err != nil {
        // Log failed attempt
        h.logFailedLogin(c.ClientIP(), loginReq.Username)
        
        c.JSON(http.StatusUnauthorized, gin.H{
            "error": "Invalid credentials",
            "code":  "INVALID_CREDENTIALS",
        })
        return
    }
    
    // Generate token pair
    tokenPair, err := h.authService.GenerateTokenPair(user.ID, user.Username, user.Role)
    if err != nil {
        log.Printf("Token generation error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Authentication failed",
            "code":  "AUTH_FAILED",
        })
        return
    }
    
    // Log successful login
    h.logSuccessfulLogin(user.ID, c.ClientIP())
    
    c.JSON(http.StatusOK, tokenPair)
}

// Secure user retrieval with proper authorization
func (h *Handler) GetUserHandler(c *gin.Context) {
    userID := c.Param("id")
    
    // Convert to int
    id, err := strconv.Atoi(userID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid user ID",
            "code":  "INVALID_USER_ID",
        })
        return
    }
    
    // Get requesting user info
    requestingUserID, _ := c.Get("user_id")
    requestingRole, _ := c.Get("role")
    
    // Authorization check: users can only view their own data or admins can view any
    if requestingUserID != id && requestingRole != "admin" {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "Access denied",
            "code":  "ACCESS_DENIED",
        })
        return
    }
    
    // Retrieve user data (without sensitive fields)
    user, err := h.getUserByID(id)
    if err != nil {
        if err == sql.ErrNoRows {
            c.JSON(http.StatusNotFound, gin.H{
                "error": "User not found",
                "code":  "USER_NOT_FOUND",
            })
            return
        }
        
        log.Printf("Database error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Internal server error",
            "code":  "INTERNAL_ERROR",
        })
        return
    }
    
    // Return sanitized user data
    response := map[string]interface{}{
        "id":       user.ID,
        "username": user.Username,
        "email":    user.Email,
        "role":     user.Role,
    }
    
    // Include sensitive data only for self or admin
    if requestingUserID == id || requestingRole == "admin" {
        response["created_at"] = user.CreatedAt
        response["last_login"] = user.LastLogin
    }
    
    c.JSON(http.StatusOK, response)
}

// Secure user update with proper authorization
func (h *Handler) UpdateUserHandler(c *gin.Context) {
    userID := c.Param("id")
    
    id, err := strconv.Atoi(userID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid user ID",
            "code":  "INVALID_USER_ID",
        })
        return
    }
    
    var updateReq struct {
        Username string `json:"username" binding:"max=50"`
        Email    string `json:"email" binding:"email,max=100"`
        Role     string `json:"role" binding:"oneof=guest user admin"`
    }
    
    if err := c.ShouldBindJSON(&updateReq); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid request format",
            "code":  "INVALID_REQUEST",
        })
        return
    }
    
    // Get requesting user info
    requestingUserID, _ := c.Get("user_id")
    requestingRole, _ := c.Get("role")
    
    // Authorization checks
    if requestingUserID != id && requestingRole != "admin" {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "Access denied",
            "code":  "ACCESS_DENIED",
        })
        return
    }
    
    // Role elevation protection: only admins can change roles
    if updateReq.Role != "" && requestingRole != "admin" {
        c.JSON(http.StatusForbidden, gin.H{
            "error": "Cannot modify role",
            "code":  "ROLE_MODIFICATION_DENIED",
        })
        return
    }
    
    // Update user
    err = h.updateUser(id, updateReq.Username, updateReq.Email, updateReq.Role)
    if err != nil {
        log.Printf("Update error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Update failed",
            "code":  "UPDATE_FAILED",
        })
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "User updated successfully",
    })
}

// Secure admin endpoint with proper authorization
func (h *Handler) AdminUsersHandler(c *gin.Context) {
    // This endpoint requires admin role (enforced by middleware)
    
    // Optional pagination and filtering
    page := c.DefaultQuery("page", "1")
    limit := c.DefaultQuery("limit", "10")
    
    pageInt, _ := strconv.Atoi(page)
    limitInt, _ := strconv.Atoi(limit)
    
    // Validate pagination parameters
    if pageInt < 1 {
        pageInt = 1
    }
    if limitInt < 1 || limitInt > 100 {
        limitInt = 10
    }
    
    users, total, err := h.getUsersPaginated(pageInt, limitInt)
    if err != nil {
        log.Printf("Database error: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Failed to retrieve users",
            "code":  "RETRIEVAL_FAILED",
        })
        return
    }
    
    // Return paginated response without sensitive data
    response := map[string]interface{}{
        "users": users,
        "pagination": map[string]interface{}{
            "page":  pageInt,
            "limit": limitInt,
            "total": total,
        },
    }
    
    c.JSON(http.StatusOK, response)
}
```

## Implementation Steps

### Step 1: Update Dependencies
```bash
# Add secure JWT and crypto libraries
go get github.com/golang-jwt/jwt/v5@latest
go get golang.org/x/crypto@latest
go get golang.org/x/time@latest  # For rate limiting

# Remove vulnerable JWT library
go mod edit -droprequire github.com/dgrijalva/jwt-go
```

### Step 2: Environment Configuration
```bash
# Create environment variables for secrets
export JWT_SECRET=$(openssl rand -base64 32)
export JWT_REFRESH_SECRET=$(openssl rand -base64 32)
export DB_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

### Step 3: Update Route Configuration
```go
func setupRoutes(r *gin.Engine, authService *auth.AuthService) {
    // Public routes (no authentication required)
    public := r.Group("/api/v1/public")
    {
        public.POST("/login", handlers.LoginHandler)
        public.POST("/register", handlers.RegisterHandler)
        public.POST("/refresh", handlers.RefreshTokenHandler)
    }
    
    // Protected routes (authentication required)
    protected := r.Group("/api/v1")
    protected.Use(middleware.AuthMiddleware(authService))
    {
        // User routes with ownership protection
        users := protected.Group("/users")
        {
            users.GET("/:id", middleware.RequireOwnership("id"), handlers.GetUserHandler)
            users.PUT("/:id", middleware.RequireOwnership("id"), handlers.UpdateUserHandler)
            users.DELETE("/:id", middleware.RequireOwnership("id"), handlers.DeleteUserHandler)
        }
        
        // Admin routes
        admin := protected.Group("/admin")
        admin.Use(middleware.RequireRole("admin"))
        {
            admin.GET("/users", handlers.AdminUsersHandler)
            admin.GET("/users/:id", handlers.AdminGetUserHandler)
            admin.PUT("/users/:id", handlers.AdminUpdateUserHandler)
        }
        
        // Regular user routes
        profile := protected.Group("/profile")
        profile.Use(middleware.RequireScope("read"))
        {
            profile.GET("/", handlers.GetProfileHandler)
            profile.PUT("/", middleware.RequireScope("write"), handlers.UpdateProfileHandler)
        }
    }
}
```

### Step 4: Add Rate Limiting
```go
package middleware

import (
    "sync"
    "time"
    
    "golang.org/x/time/rate"
    "github.com/gin-gonic/gin"
)

type RateLimiter struct {
    visitors map[string]*rate.Limiter
    mu       sync.RWMutex
    r        rate.Limit
    b        int
}

func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
    return &RateLimiter{
        visitors: make(map[string]*rate.Limiter),
        r:        r,
        b:        b,
    }
}

func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    limiter, exists := rl.visitors[ip]
    if !exists {
        limiter = rate.NewLimiter(rl.r, rl.b)
        rl.visitors[ip] = limiter
    }
    
    return limiter
}

func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        limiter := rl.GetLimiter(c.ClientIP())
        
        if !limiter.Allow() {
            c.JSON(429, gin.H{
                "error": "Rate limit exceeded",
                "code":  "RATE_LIMITED",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

## Security Testing

### Authentication Tests
```go
func TestJWTAuthentication(t *testing.T) {
    authService, _ := auth.NewAuthService()
    
    // Test valid token generation
    tokenPair, err := authService.GenerateTokenPair(1, "testuser", "user")
    assert.NoError(t, err)
    assert.NotEmpty(t, tokenPair.AccessToken)
    
    // Test token validation
    claims, err := authService.ValidateToken(tokenPair.AccessToken, "access")
    assert.NoError(t, err)
    assert.Equal(t, 1, claims.UserID)
    
    // Test expired token rejection
    expiredToken := createExpiredToken()
    _, err = authService.ValidateToken(expiredToken, "access")
    assert.Error(t, err)
}

func TestAuthorizationMiddleware(t *testing.T) {
    router := setupTestRouter()
    
    // Test unauthorized access
    req := httptest.NewRequest("GET", "/api/v1/users/1", nil)
    resp := httptest.NewRecorder()
    router.ServeHTTP(resp, req)
    assert.Equal(t, 401, resp.Code)
    
    // Test authorized access
    token := generateTestToken(1, "user")
    req = httptest.NewRequest("GET", "/api/v1/users/1", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp = httptest.NewRecorder()
    router.ServeHTTP(resp, req)
    assert.Equal(t, 200, resp.Code)
    
    // Test IDOR protection
    req = httptest.NewRequest("GET", "/api/v1/users/2", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    resp = httptest.NewRecorder()
    router.ServeHTTP(resp, req)
    assert.Equal(t, 403, resp.Code)
}
```

## Best Practices Summary

### Authentication Best Practices
1. **Use strong JWT secrets** - Generate cryptographically secure secrets
2. **Implement token expiration** - Short-lived access tokens (15 minutes)
3. **Use refresh tokens** - Separate tokens for token renewal
4. **Validate token claims** - Check issuer, audience, expiration
5. **Log authentication events** - Monitor failed login attempts

### Authorization Best Practices
1. **Principle of least privilege** - Grant minimal required permissions
2. **Role-based access control** - Implement hierarchical roles
3. **Resource ownership** - Users can only access their own data
4. **Scope-based permissions** - Fine-grained permission control
5. **Regular permission audits** - Review and update access controls

### Additional Security Measures
1. **Rate limiting** - Prevent brute force attacks
2. **Input validation** - Validate all API inputs
3. **Output filtering** - Don't expose sensitive data
4. **Audit logging** - Log all security-relevant events
5. **Security headers** - Implement proper HTTP security headers

## Additional Resources

- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)