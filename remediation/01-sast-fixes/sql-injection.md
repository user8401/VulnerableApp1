# SQL Injection Vulnerability Remediation

## Problem Description

SQL injection vulnerabilities occur when user input is directly concatenated into SQL queries without proper sanitization or parameterization. This allows attackers to manipulate SQL queries and potentially access, modify, or delete data.

## Vulnerable Code Examples

### Current Vulnerable Code in `main.go`:

```go
// VULNERABLE: Direct string concatenation in search
func searchHandler(c *gin.Context) {
    query := c.Query("q")
    sqlQuery := "SELECT id, username, email FROM users WHERE username LIKE '%" + query + "%'"
    rows, err := db.Query(sqlQuery)
    // ...
}

// VULNERABLE: Direct string concatenation in login
func loginHandler(c *gin.Context) {
    username := c.PostForm("username")
    password := c.PostForm("password")
    query := "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    err := db.QueryRow(query).Scan(&user.ID, &user.Username, &user.Role)
    // ...
}
```

## Fixed Code Examples

### 1. Using Parameterized Queries (Recommended)

```go
// SECURE: Using parameterized queries
func searchHandler(c *gin.Context) {
    query := c.Query("q")
    
    // Input validation
    if len(query) > 100 {
        c.JSON(400, gin.H{"error": "Search query too long"})
        return
    }
    
    // Parameterized query prevents SQL injection
    sqlQuery := "SELECT id, username, email FROM users WHERE username LIKE ?"
    searchPattern := "%" + query + "%"
    rows, err := db.Query(sqlQuery, searchPattern)
    if err != nil {
        log.Printf("Database error: %v", err)
        c.JSON(500, gin.H{"error": "Internal server error"})
        return
    }
    defer rows.Close()

    var users []User
    for rows.Next() {
        var user User
        err := rows.Scan(&user.ID, &user.Username, &user.Email)
        if err != nil {
            log.Printf("Scan error: %v", err)
            continue
        }
        users = append(users, user)
    }

    c.HTML(200, "search.html", gin.H{
        "users": users,
        "query": template.HTMLEscapeString(query), // Also escape for XSS protection
    })
}

// SECURE: Using parameterized queries with password hashing
func loginHandler(c *gin.Context) {
    username := c.PostForm("username")
    password := c.PostForm("password")

    // Input validation
    if len(username) == 0 || len(password) == 0 {
        c.HTML(200, "login.html", gin.H{"error": "Username and password required"})
        return
    }
    
    if len(username) > 50 || len(password) > 100 {
        c.HTML(200, "login.html", gin.H{"error": "Invalid credentials"})
        return
    }

    var user User
    var hashedPassword string
    
    // Parameterized query prevents SQL injection
    query := "SELECT id, username, role, password FROM users WHERE username = ?"
    err := db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Role, &hashedPassword)
    
    if err != nil {
        // Don't reveal whether user exists or not
        c.HTML(200, "login.html", gin.H{"error": "Invalid credentials"})
        return
    }

    // Verify password hash (assuming you're using bcrypt)
    if !checkPasswordHash(password, hashedPassword) {
        c.HTML(200, "login.html", gin.H{"error": "Invalid credentials"})
        return
    }

    // Create secure session
    session, _ := store.Get(c.Request, "session")
    session.Values["user_id"] = user.ID
    session.Values["username"] = user.Username
    session.Values["role"] = user.Role
    session.Options.Secure = true  // Only send over HTTPS
    session.Options.HttpOnly = true // Prevent XSS access
    session.Options.SameSite = http.SameSiteStrictMode
    session.Save(c.Request, c.Writer)

    c.Redirect(302, "/profile")
}
```

### 2. Password Hashing Functions

```go
import "golang.org/x/crypto/bcrypt"

// Hash password before storing
func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}

// Check password against hash
func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
```

### 3. Input Validation Helper

```go
import (
    "regexp"
    "unicode/utf8"
)

// Validate and sanitize user input
func validateInput(input string, maxLength int, allowedChars string) error {
    if len(input) == 0 {
        return errors.New("input required")
    }
    
    if len(input) > maxLength {
        return errors.New("input too long")
    }
    
    if !utf8.ValidString(input) {
        return errors.New("invalid characters")
    }
    
    if allowedChars != "" {
        matched, _ := regexp.MatchString(allowedChars, input)
        if !matched {
            return errors.New("invalid characters")
        }
    }
    
    return nil
}
```

## Implementation Steps

### Step 1: Update Dependencies
Add password hashing dependency to `go.mod`:
```
go get golang.org/x/crypto/bcrypt
```

### Step 2: Create Password Migration
Create a script to hash existing passwords:
```go
func migratePasswords() {
    rows, err := db.Query("SELECT id, password FROM users")
    if err != nil {
        log.Fatal(err)
    }
    defer rows.Close()

    for rows.Next() {
        var id int
        var plainPassword string
        rows.Scan(&id, &plainPassword)
        
        hashedPassword, err := hashPassword(plainPassword)
        if err != nil {
            log.Printf("Error hashing password for user %d: %v", id, err)
            continue
        }
        
        _, err = db.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, id)
        if err != nil {
            log.Printf("Error updating password for user %d: %v", id, err)
        }
    }
}
```

### Step 3: Update Database Schema
Add constraints and indexes:
```sql
-- Add constraints to prevent SQL injection through database design
ALTER TABLE users ADD CONSTRAINT username_length CHECK (length(username) <= 50);
ALTER TABLE users ADD CONSTRAINT email_format CHECK (email LIKE '%@%');

-- Add indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
```

### Step 4: Replace All String Concatenation
Search for patterns like:
- `"SELECT ... " + variable`
- `fmt.Sprintf("SELECT ... %s", variable)`
- Direct concatenation in any SQL query

Replace with parameterized queries using `?` placeholders.

## Testing SQL Injection Fixes

### Test Cases
1. **Basic injection**: `' OR '1'='1`
2. **Union injection**: `' UNION SELECT password FROM users--`
3. **Boolean-based**: `' AND 1=1--`
4. **Time-based**: `'; WAITFOR DELAY '00:00:05'--`

### Automated Testing
```go
func TestSQLInjectionPrevention(t *testing.T) {
    maliciousInputs := []string{
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "' UNION SELECT password FROM users--",
        "admin'--",
    }
    
    for _, input := range maliciousInputs {
        resp := httptest.NewRecorder()
        req, _ := http.NewRequest("GET", "/search?q="+url.QueryEscape(input), nil)
        router.ServeHTTP(resp, req)
        
        // Should not return all users or cause errors
        assert.NotContains(t, resp.Body.String(), "admin@example.com")
        assert.Equal(t, 200, resp.Code)
    }
}
```

## Prevention Best Practices

1. **Always use parameterized queries** - Never concatenate user input into SQL
2. **Validate all input** - Check length, format, and content
3. **Use least privilege** - Database users should have minimal required permissions
4. **Hash passwords** - Never store plain text passwords
5. **Log security events** - Monitor for injection attempts
6. **Regular security testing** - Use automated tools to scan for SQL injection
7. **Code review** - Have peers review all database interaction code

## Tools for Detection

- **SAST Tools**: SonarQube, CodeQL, Semgrep, Checkmarx
- **DAST Tools**: OWASP ZAP, Burp Suite, SQLmap
- **Manual Testing**: Use SQL injection payloads in all input fields

## Additional Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Go database/sql documentation](https://pkg.go.dev/database/sql)
- [SQL Injection Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)