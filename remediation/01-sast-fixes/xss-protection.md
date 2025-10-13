# Cross-Site Scripting (XSS) Protection

## Problem Description

Cross-Site Scripting (XSS) vulnerabilities occur when user input is displayed on web pages without proper validation, sanitization, or encoding. This allows attackers to inject malicious scripts that execute in other users' browsers.

## Types of XSS

1. **Stored XSS** - Malicious script stored in database (like our comments system)
2. **Reflected XSS** - Malicious script reflected from URL parameters
3. **DOM-based XSS** - Client-side script manipulation

## Vulnerable Code Examples

### Current Vulnerable Code in Templates:

```html
<!-- VULNERABLE: templates/comments.html -->
<div class="comment-content">{{.Content}}</div>

<!-- VULNERABLE: templates/search.html -->
<input type="text" value="{{.query}}" placeholder="Enter username">
```

## Fixed Code Examples

### 1. Server-Side Output Encoding (Go Templates)

```html
<!-- SECURE: Properly escaped output -->
<div class="comment-content">{{.Content | html}}</div>

<!-- OR using explicit escaping -->
<div class="comment-content">{{html .Content}}</div>

<!-- SECURE: Escaped in input attributes -->
<input type="text" value="{{.query | html}}" placeholder="Enter username">
```

### 2. Server-Side Input Validation and Sanitization

```go
import (
    "html"
    "regexp"
    "strings"
    "github.com/microcosm-cc/bluemonday"
)

// Input validation and sanitization
func sanitizeInput(input string) string {
    // Remove any null bytes
    input = strings.ReplaceAll(input, "\x00", "")
    
    // Limit length
    if len(input) > 1000 {
        input = input[:1000]
    }
    
    // HTML escape for basic protection
    input = html.EscapeString(input)
    
    return input
}

// Advanced sanitization using bluemonday
func sanitizeHTML(input string) string {
    // Create a strict policy that allows no HTML
    p := bluemonday.StrictPolicy()
    return p.Sanitize(input)
}

// Allow only safe HTML tags (for rich content)
func sanitizeHTMLAllowSafe(input string) string {
    p := bluemonday.UGCPolicy()
    // Allow only safe tags like <p>, <strong>, <em>, etc.
    return p.Sanitize(input)
}

// SECURE: Updated comment handler
func addCommentHandler(c *gin.Context) {
    content := c.PostForm("content")
    
    // Input validation
    if len(content) == 0 {
        c.JSON(400, gin.H{"error": "Comment content required"})
        return
    }
    
    if len(content) > 1000 {
        c.JSON(400, gin.H{"error": "Comment too long (max 1000 characters)"})
        return
    }
    
    // Sanitize the content
    content = sanitizeInput(content)
    
    userID := 1 // Get from session in real implementation
    
    _, err := db.Exec("INSERT INTO comments (user_id, content, date) VALUES (?, ?, ?)",
        userID, content, time.Now().Format("2006-01-02 15:04:05"))
    
    if err != nil {
        log.Printf("Database error: %v", err)
        c.JSON(500, gin.H{"error": "Internal server error"})
        return
    }

    c.Redirect(302, "/comments")
}
```

### 3. Content Security Policy (CSP) Headers

```go
// Add CSP middleware
func CSPMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Strict CSP that prevents inline scripts
        cspPolicy := "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'"
        
        c.Header("Content-Security-Policy", cspPolicy)
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        
        c.Next()
    }
}

// Apply middleware in main()
func main() {
    // ... existing code ...
    
    r := gin.Default()
    r.Use(CSPMiddleware()) // Add CSP middleware
    
    // ... rest of the routes ...
}
```

### 4. Updated Templates with Proper Escaping

```html
<!-- SECURE: templates/comments.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Comments</title>
    <link rel="stylesheet" href="/static/style.css">
    <meta charset="UTF-8">
    <!-- CSP meta tag as fallback -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self';">
</head>
<body>
    <nav>
        <a href="/">Home</a>
        <a href="/login">Login</a>
        <a href="/register">Register</a>
        <a href="/profile">Profile</a>
        <a href="/comments">Comments</a>
        <a href="/search">Search</a>
    </nav>
    
    <div class="container">
        <h1>Comments</h1>
        
        <div class="add-comment">
            <h2>Add Comment</h2>
            <form method="POST" action="/comments">
                <div class="form-group">
                    <label for="content">Comment (max 1000 characters):</label>
                    <textarea id="content" name="content" rows="4" maxlength="1000" required></textarea>
                    <small>HTML tags will be escaped for security</small>
                </div>
                <button type="submit">Add Comment</button>
            </form>
        </div>
        
        <div class="comments-list">
            <h2>All Comments</h2>
            {{range .comments}}
            <div class="comment">
                <div class="comment-meta">
                    <strong>User ID: {{.UserID}}</strong> - {{.Date}}
                </div>
                <!-- SECURE: Content is properly escaped -->
                <div class="comment-content">{{.Content | html}}</div>
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>
```

```html
<!-- SECURE: templates/search.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Search Users</title>
    <link rel="stylesheet" href="/static/style.css">
    <meta charset="UTF-8">
</head>
<body>
    <!-- ... navigation ... -->
    
    <div class="container">
        <h1>Search Users</h1>
        
        <form method="GET" action="/search">
            <div class="form-group">
                <label for="q">Search:</label>
                <!-- SECURE: Properly escaped value attribute -->
                <input type="text" id="q" name="q" value="{{.query | html}}" 
                       placeholder="Enter username to search" maxlength="100">
            </div>
            <button type="submit">Search</button>
        </form>
        
        {{if .users}}
        <div class="search-results">
            <h2>Search Results:</h2>
            {{range .users}}
            <div class="user-result">
                <p><strong>ID:</strong> {{.ID}}</p>
                <!-- SECURE: All output is escaped -->
                <p><strong>Username:</strong> {{.Username | html}}</p>
                <p><strong>Email:</strong> {{.Email | html}}</p>
            </div>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
```

### 5. Client-Side Protection (JavaScript)

```javascript
// static/security.js - Client-side XSS protection utilities

// Escape HTML in JavaScript
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Safe way to set content
function setSafeContent(element, content) {
    element.textContent = content; // Use textContent instead of innerHTML
}

// Validate form inputs
function validateComment(content) {
    if (content.length === 0) {
        alert('Comment cannot be empty');
        return false;
    }
    
    if (content.length > 1000) {
        alert('Comment too long (max 1000 characters)');
        return false;
    }
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
        /<script/i,
        /javascript:/i,
        /on\w+=/i,
        /<iframe/i,
        /<object/i,
        /<embed/i
    ];
    
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(content)) {
            alert('Invalid content detected');
            return false;
        }
    }
    
    return true;
}

// Add validation to comment form
document.addEventListener('DOMContentLoaded', function() {
    const commentForm = document.querySelector('form[action="/comments"]');
    if (commentForm) {
        commentForm.addEventListener('submit', function(e) {
            const content = document.getElementById('content').value;
            if (!validateComment(content)) {
                e.preventDefault();
            }
        });
    }
});
```

## Implementation Steps

### Step 1: Update Dependencies
Add HTML sanitization library:
```bash
go get github.com/microcosm-cc/bluemonday
```

### Step 2: Update Templates
- Add `| html` to all user-generated content
- Set proper charset and CSP meta tags
- Add input validation attributes (maxlength, etc.)

### Step 3: Add Server-Side Protection
- Implement input validation and sanitization
- Add CSP middleware
- Update all handlers that process user input

### Step 4: Add Client-Side Protection
- Include JavaScript validation
- Use textContent instead of innerHTML
- Validate forms before submission

## Testing XSS Fixes

### Test Payloads
```javascript
// Basic XSS payloads to test
const xssPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    'javascript:alert("XSS")',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<div onmouseover="alert(\'XSS\')">Hover me</div>',
    '"><script>alert("XSS")</script>',
    '\"><script>alert(String.fromCharCode(88,83,83))</script>'
];
```

### Automated Testing
```go
func TestXSSPrevention(t *testing.T) {
    xssPayloads := []string{
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
    }
    
    for _, payload := range xssPayloads {
        // Test comment submission
        form := url.Values{}
        form.Add("content", payload)
        
        resp := httptest.NewRecorder()
        req, _ := http.NewRequest("POST", "/comments", strings.NewReader(form.Encode()))
        req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
        
        router.ServeHTTP(resp, req)
        
        // Check that script tags are escaped or removed
        assert.NotContains(t, resp.Body.String(), "<script>")
        assert.NotContains(t, resp.Body.String(), "onerror=")
    }
}
```

## Prevention Best Practices

1. **Output Encoding** - Always encode user data when displaying
2. **Input Validation** - Validate and sanitize all user input
3. **Content Security Policy** - Implement strict CSP headers
4. **Use Safe APIs** - Use textContent instead of innerHTML
5. **Avoid Dangerous Functions** - Don't use eval(), document.write()
6. **Regular Testing** - Test with XSS payloads regularly
7. **Security Headers** - Implement all relevant security headers

## Tools for Detection

- **SAST Tools**: SonarQube, CodeQL, ESLint security rules
- **DAST Tools**: OWASP ZAP, Burp Suite, XSStrike
- **Browser Tools**: Chrome DevTools Security tab
- **Manual Testing**: Try XSS payloads in all input fields

## Additional Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Go Template Security](https://pkg.go.dev/html/template)