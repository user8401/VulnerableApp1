package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var store = sessions.NewCookieStore([]byte("secret-key"))

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
	APIKey   string `json:"api_key"`
}

type Comment struct {
	ID      int    `json:"id"`
	UserID  int    `json:"user_id"`
	Content string `json:"content"`
	Date    string `json:"date"`
}

func main() {
	initDB()
	defer db.Close()

	// Vulnerable: Running with debug mode in production
	gin.SetMode(gin.DebugMode)
	r := gin.Default()

	// Load HTML templates
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// Web routes
	r.GET("/", homeHandler)
	r.GET("/login", loginPageHandler)
	r.POST("/login", loginHandler)
	r.GET("/register", registerPageHandler)
	r.POST("/register", registerHandler)
	r.GET("/profile", profileHandler)
	r.GET("/comments", commentsHandler)
	r.POST("/comments", addCommentHandler)
	r.GET("/search", searchHandler)

	// Vulnerable API routes
	api := r.Group("/api/v1")
	{
		api.GET("/users", getAllUsersHandler)       // Vulnerable: No authentication required
		api.GET("/users/:id", getUserHandler)       // Vulnerable: IDOR
		api.PUT("/users/:id", updateUserHandler)    // Vulnerable: No authorization check
		api.DELETE("/users/:id", deleteUserHandler) // Vulnerable: No authorization check
		api.GET("/admin/users", adminUsersHandler)  // Vulnerable: Broken access control
		api.POST("/auth", authHandler)              // Vulnerable: Weak JWT implementation
		api.GET("/data", dataHandler)               // Vulnerable: Excessive data exposure

		// UNDOCUMENTED API: Not in Swagger - Shadow API for API inventory discovery
		api.GET("/internal/debug", debugHandler)    // Vulnerable: Undocumented debug endpoint
		api.POST("/internal/backup", backupHandler) // Vulnerable: Undocumented backup endpoint
		api.GET("/internal/logs", logsHandler)      // Vulnerable: Undocumented logs endpoint
	}

	fmt.Println("Server starting on :8080")
	log.Fatal(r.Run(":8080"))
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./vulnerable.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create tables
	createTables := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		email TEXT NOT NULL,
		password TEXT NOT NULL,
		role TEXT DEFAULT 'user',
		api_key TEXT
	);

	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		content TEXT,
		date TEXT,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);

	INSERT OR IGNORE INTO users (id, username, email, password, role, api_key) 
	VALUES (1, 'admin', 'admin@example.com', 'admin123', 'admin', 'admin-secret-key');
	`

	_, err = db.Exec(createTables)
	if err != nil {
		log.Fatal(err)
	}
}

// Vulnerable: SQL Injection in search functionality
func searchHandler(c *gin.Context) {
	query := c.Query("q")

	// VULNERABLE: Direct string concatenation leads to SQL injection
	sqlQuery := "SELECT id, username, email FROM users WHERE username LIKE '%" + query + "%'"

	rows, err := db.Query(sqlQuery)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	c.HTML(200, "search.html", gin.H{
		"users": users,
		"query": query,
	})
}

// Vulnerable: XSS in comment display
func commentsHandler(c *gin.Context) {
	rows, err := db.Query("SELECT id, user_id, content, date FROM comments ORDER BY date DESC")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		err := rows.Scan(&comment.ID, &comment.UserID, &comment.Content, &comment.Date)
		if err != nil {
			continue
		}
		comments = append(comments, comment)
	}

	c.HTML(200, "comments.html", gin.H{
		"comments": comments,
	})
}

func addCommentHandler(c *gin.Context) {
	content := c.PostForm("content")
	userID := 1 // Simplified for demo

	_, err := db.Exec("INSERT INTO comments (user_id, content, date) VALUES (?, ?, ?)",
		userID, content, time.Now().Format("2006-01-02 15:04:05"))

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.Redirect(302, "/comments")
}

func homeHandler(c *gin.Context) {
	c.HTML(200, "index.html", gin.H{
		"title": "Vulnerable Web App",
	})
}

func loginPageHandler(c *gin.Context) {
	c.HTML(200, "login.html", nil)
}

// Vulnerable: Weak authentication
func loginHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// VULNERABLE: SQL Injection in login
	query := "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'"

	var user User
	err := db.QueryRow(query).Scan(&user.ID, &user.Username, &user.Role)

	if err != nil {
		c.HTML(200, "login.html", gin.H{"error": "Invalid credentials"})
		return
	}

	// Vulnerable: Weak session management
	session, _ := store.Get(c.Request, "session")
	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["role"] = user.Role
	session.Save(c.Request, c.Writer)

	c.Redirect(302, "/profile")
}

func registerPageHandler(c *gin.Context) {
	c.HTML(200, "register.html", nil)
}

func registerHandler(c *gin.Context) {
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")

	// Vulnerable: No input validation, storing plain text passwords
	_, err := db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
		username, email, password)

	if err != nil {
		c.HTML(200, "register.html", gin.H{"error": "Registration failed"})
		return
	}

	c.Redirect(302, "/login")
}

func profileHandler(c *gin.Context) {
	session, _ := store.Get(c.Request, "session")
	userID, exists := session.Values["user_id"]

	if !exists {
		c.Redirect(302, "/login")
		return
	}

	var user User
	err := db.QueryRow("SELECT id, username, email, role FROM users WHERE id = ?", userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.Role)

	if err != nil {
		c.Redirect(302, "/login")
		return
	}

	c.HTML(200, "profile.html", gin.H{
		"user": user,
	})
}

// API Handlers with vulnerabilities

// Vulnerable: No authentication required for sensitive data
func getAllUsersHandler(c *gin.Context) {
	rows, err := db.Query("SELECT id, username, email, password, role, api_key FROM users")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Role, &user.APIKey)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	// Vulnerable: Exposing sensitive data including passwords and API keys
	c.JSON(200, users)
}

// Vulnerable: IDOR (Insecure Direct Object Reference)
func getUserHandler(c *gin.Context) {
	id := c.Param("id")

	var user User
	err := db.QueryRow("SELECT id, username, email, password, role, api_key FROM users WHERE id = ?", id).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password, &user.Role, &user.APIKey)

	if err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// Vulnerable: No authorization check - any user can view any other user's data
	c.JSON(200, user)
}

// Vulnerable: No authorization check
func updateUserHandler(c *gin.Context) {
	id := c.Param("id")

	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Vulnerable: No authorization - any user can update any other user
	_, err := db.Exec("UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?",
		user.Username, user.Email, user.Role, id)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "User updated"})
}

// Vulnerable: No authorization check for deletion
func deleteUserHandler(c *gin.Context) {
	id := c.Param("id")

	// Vulnerable: No authorization check
	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "User deleted"})
}

// Vulnerable: Broken access control
func adminUsersHandler(c *gin.Context) {
	// Vulnerable: No proper admin role verification
	apiKey := c.GetHeader("X-API-Key")
	if apiKey == "" {
		c.JSON(401, gin.H{"error": "API key required"})
		return
	}

	// Vulnerable: Hardcoded API key check
	if apiKey != "admin-secret-key" {
		c.JSON(403, gin.H{"error": "Access denied"})
		return
	}

	rows, err := db.Query("SELECT id, username, email, role FROM users")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	c.JSON(200, users)
}

// Vulnerable: Weak JWT implementation
func authHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	var user User
	err := db.QueryRow("SELECT id, username, role FROM users WHERE username = ? AND password = ?",
		username, password).Scan(&user.ID, &user.Username, &user.Role)

	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// Vulnerable: Weak JWT secret and no expiration
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
	})

	// Vulnerable: Weak secret key
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		c.JSON(500, gin.H{"error": "Could not create token"})
		return
	}

	c.JSON(200, gin.H{"token": tokenString})
}

// Vulnerable: Excessive data exposure
func dataHandler(c *gin.Context) {
	// Vulnerable: No rate limiting, exposing all data
	rows, err := db.Query(`
		SELECT u.id, u.username, u.email, u.password, u.role, u.api_key,
		       c.content, c.date
		FROM users u 
		LEFT JOIN comments c ON u.id = c.user_id
	`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var data []map[string]interface{}
	for rows.Next() {
		var userID, username, email, password, role, apiKey, content, date sql.NullString
		err := rows.Scan(&userID, &username, &email, &password, &role, &apiKey, &content, &date)
		if err != nil {
			continue
		}

		record := map[string]interface{}{
			"user_id":  userID.String,
			"username": username.String,
			"email":    email.String,
			"password": password.String, // Vulnerable: Exposing passwords
			"role":     role.String,
			"api_key":  apiKey.String, // Vulnerable: Exposing API keys
			"content":  content.String,
			"date":     date.String,
		}
		data = append(data, record)
	}

	c.JSON(200, data)
}

// UNDOCUMENTED ENDPOINTS - Not in Swagger documentation (Shadow APIs)

// Vulnerable: Debug endpoint exposing sensitive system information
func debugHandler(c *gin.Context) {
	// Vulnerable: No authentication required for debug endpoint
	// Vulnerable: Exposing sensitive system information
	debugInfo := map[string]interface{}{
		"version":      "1.0.0",
		"environment":  "production", // Vulnerable: Debug in production
		"database_url": "sqlite://./vulnerable.db",
		"jwt_secret":   "secret", // Vulnerable: Exposing JWT secret
		"admin_key":    "admin-secret-key",
		"uptime":       time.Since(time.Now().Add(-time.Hour)).String(),
		"memory_usage": "125MB",
		"go_version":   "go1.19",
		"git_commit":   "abc123def456",
		"build_time":   "2024-01-15T10:30:00Z",
		"config": map[string]interface{}{
			"debug_mode":     true,
			"log_level":      "debug",
			"db_password":    "supersecret123", // Vulnerable: Password in debug
			"api_rate_limit": 0,                // Vulnerable: No rate limiting
		},
	}

	c.JSON(200, debugInfo)
}

// Vulnerable: Backup endpoint without proper authorization
func backupHandler(c *gin.Context) {
	// Vulnerable: No authentication required
	// Vulnerable: Potential path traversal
	backupType := c.DefaultQuery("type", "full")

	// Simulate backup operation
	backup := map[string]interface{}{
		"backup_id": "backup_" + time.Now().Format("20060102_150405"),
		"type":      backupType,
		"status":    "completed",
		"size":      "2.5MB",
		"location":  "/backups/db_backup.sql", // Vulnerable: Exposing file paths
		"tables": []string{
			"users",
			"comments",
			"sessions", // Vulnerable: Exposing table structure
		},
		"user_count":    1,
		"comment_count": 0,
		"created_at":    time.Now().Format("2006-01-02 15:04:05"),
	}

	// Vulnerable: Actually perform backup without authorization
	if backupType == "users" {
		rows, err := db.Query("SELECT id, username, email, password FROM users")
		if err == nil {
			var users []map[string]interface{}
			for rows.Next() {
				var id int
				var username, email, password string
				rows.Scan(&id, &username, &email, &password)
				users = append(users, map[string]interface{}{
					"id":       id,
					"username": username,
					"email":    email,
					"password": password, // Vulnerable: Exposing passwords in backup
				})
			}
			backup["data"] = users
			rows.Close()
		}
	}

	c.JSON(200, backup)
}

// Vulnerable: Logs endpoint exposing sensitive information
func logsHandler(c *gin.Context) {
	// Vulnerable: No authentication required
	// Vulnerable: Exposing sensitive log data
	logLevel := c.DefaultQuery("level", "info")
	lines := c.DefaultQuery("lines", "50")

	// Simulate log entries with sensitive information
	logs := []map[string]interface{}{
		{
			"timestamp": time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05"),
			"level":     "INFO",
			"message":   "Application started on port 8080",
			"details":   "gin.Mode = debug",
		},
		{
			"timestamp":  time.Now().Add(-45 * time.Minute).Format("2006-01-02 15:04:05"),
			"level":      "WARN",
			"message":    "Failed login attempt",
			"username":   "admin", // Vulnerable: Exposing usernames in logs
			"ip":         "192.168.1.100",
			"user_agent": "Mozilla/5.0...",
		},
		{
			"timestamp": time.Now().Add(-30 * time.Minute).Format("2006-01-02 15:04:05"),
			"level":     "ERROR",
			"message":   "Database connection error",
			"error":     "dial tcp 127.0.0.1:3306: connect: connection refused",
			"db_url":    "user:password@tcp(localhost:3306)/vulnerable", // Vulnerable: DB credentials in logs
		},
		{
			"timestamp": time.Now().Add(-15 * time.Minute).Format("2006-01-02 15:04:05"),
			"level":     "DEBUG",
			"message":   "SQL Query executed",
			"query":     "SELECT * FROM users WHERE username = 'admin' AND password = 'admin123'", // Vulnerable: Passwords in logs
			"duration":  "2.5ms",
		},
		{
			"timestamp": time.Now().Add(-5 * time.Minute).Format("2006-01-02 15:04:05"),
			"level":     "INFO",
			"message":   "JWT token generated",
			"user_id":   1,
			"username":  "admin",
			"token":     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", // Vulnerable: Token in logs
		},
	}

	// Filter by log level if specified
	if logLevel != "all" {
		filteredLogs := []map[string]interface{}{}
		for _, log := range logs {
			if strings.ToLower(log["level"].(string)) == strings.ToLower(logLevel) {
				filteredLogs = append(filteredLogs, log)
			}
		}
		logs = filteredLogs
	}

	response := map[string]interface{}{
		"total_lines": len(logs),
		"level":       logLevel,
		"lines":       lines,
		"logs":        logs,
		"log_file":    "/var/log/vulnerable-app.log", // Vulnerable: Exposing file paths
	}

	c.JSON(200, response)
}
