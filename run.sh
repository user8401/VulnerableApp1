#!/bin/bash

# Build and run script for the vulnerable web application

echo "🚨 WARNING: This application contains intentional security vulnerabilities!"
echo "Do not deploy in production or on systems connected to the internet."
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.19 or later."
    exit 1
fi

echo "📦 Downloading dependencies..."
go mod download

if [ $? -ne 0 ]; then
    echo "❌ Failed to download dependencies"
    exit 1
fi

echo "🔨 Building application..."
go build -o vulnerable-app main.go

if [ $? -ne 0 ]; then
    echo "❌ Failed to build application"
    exit 1
fi

echo "🚀 Starting vulnerable web application..."
echo "📍 Application will be available at: http://localhost:8080"
echo "📚 Default credentials: admin / admin123"
echo ""
echo "Press Ctrl+C to stop the application"
echo ""

./vulnerable-app