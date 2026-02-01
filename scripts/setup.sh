#!/bin/bash

echo "Setting up Secure Notes project..."

# Create necessary directories
mkdir -p data
mkdir -p backups
mkdir -p logs
mkdir -p bin

# Set secure permissions
chmod 700 data
chmod 700 backups
chmod 700 logs

# Copy .env.example to .env if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env file. Please update with your keys!"
fi

# Install SQLCipher if not installed
if ! command -v sqlcipher &> /dev/null; then
    echo "SQLCipher not found. Please install it:"
    echo "  Ubuntu/Debian: sudo apt-get install libsqlcipher-dev"
    echo "  macOS: brew install sqlcipher"
fi

# Download Go dependencies
go mod download

echo "Setup complete!"
echo "Please update .env file with secure encryption keys before running."