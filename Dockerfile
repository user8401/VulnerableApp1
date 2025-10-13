# Vulnerable Dockerfile with multiple security issues

# VULNERABLE: Using outdated base image with known vulnerabilities
FROM ubuntu:18.04

# VULNERABLE: Running as root user
USER root

# VULNERABLE: Not pinning package versions
RUN apt-get update && apt-get install -y \
    golang-go \
    sqlite3 \
    curl \
    wget \
    vim \
    && rm -rf /var/lib/apt/lists/*

# VULNERABLE: Setting weak file permissions
RUN chmod 777 /tmp

# VULNERABLE: Exposing sensitive build arguments
ARG DATABASE_PASSWORD=supersecret123
ARG API_KEY=admin-secret-key

# VULNERABLE: Setting environment variables with sensitive data
ENV DB_PASSWORD=${DATABASE_PASSWORD}
ENV SECRET_KEY=${API_KEY}
ENV DEBUG=true

# VULNERABLE: Creating user with predictable UID/GID
RUN groupadd -g 1000 appuser && \
    useradd -r -u 1000 -g appuser appuser

# Set working directory
WORKDIR /app

# Copy application files
COPY . .

# VULNERABLE: Not using multi-stage build, exposing source code
# VULNERABLE: Not running dependency scan

# Build the application
RUN go mod download
RUN go build -o vulnerable-app main.go

# VULNERABLE: Changing back to root for final operations
USER root

# VULNERABLE: Installing additional packages without version pinning
RUN apt-get update && apt-get install -y netcat

# VULNERABLE: Setting overly permissive file permissions
RUN chmod 755 /app/vulnerable-app
RUN chown -R appuser:appuser /app

# VULNERABLE: Exposing unnecessary ports
EXPOSE 8080
EXPOSE 22
EXPOSE 3306

# VULNERABLE: Not using non-root user for runtime
# USER appuser

# VULNERABLE: Not using HEALTHCHECK
# VULNERABLE: Not setting resource limits

# VULNERABLE: Running with elevated privileges
CMD ["./vulnerable-app"]