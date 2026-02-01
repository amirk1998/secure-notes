# Secure Notes - SQLite Security Demonstration

A comprehensive demonstration of SQLite security best practices in Go, featuring database encryption, field-level encryption, audit logging, rate limiting, and automated backups.

## Features

### 🔒 Security Features
- **Database Encryption**: Full database encryption using SQLCipher
- **Field-Level Encryption**: AES-256-GCM encryption for sensitive note content
- **Password Hashing**: Argon2id for secure password storage
- **SQL Injection Prevention**: Parameterized queries throughout
- **Rate Limiting**: Per-user and per-operation rate limiting
- **Account Lockout**: Automatic account locking after failed login attempts

### 📊 Audit & Monitoring
- **Comprehensive Audit Logging**: All operations logged to database and file
- **Security Monitoring**: Automatic detection of suspicious activities
- **Failed Login Detection**: Alerts on multiple failed login attempts
- **Async Logging**: High-performance asynchronous audit logging

### 💾 Backup & Recovery
- **Encrypted Backups**: AES-256 encrypted and compressed backups
- **Automated Backups**: Scheduled backup creation
- **Checksum Verification**: SHA-256 checksums for backup integrity
- **Retention Policy**: Automatic cleanup of old backups

### 🛡️ Additional Security
- **Secure File Permissions**: 0600 permissions on sensitive files
- **Input Validation**: Comprehensive validation of all user inputs
- **Session Management**: Secure session token generation
- **Transaction Isolation**: Serializable isolation level for critical operations

## Installation

### Prerequisites
```bash
# Install SQLCipher
# Ubuntu/Debian
sudo apt-get install libsqlcipher-dev

# macOS
brew install sqlcipher
```

### Setup
```bash
# Clone repository
git clone https://github.com/yourusername/secure-notes
cd secure-notes

# Run setup script
make setup

# Update .env file with your encryption keys
nano .env

# Install dependencies
make deps

# Build application
make build
```

## Configuration

Edit `.env` file:

```bash
# IMPORTANT: Use strong, unique keys (minimum 32 characters)
DB_ENCRYPTION_KEY=your-very-strong-database-encryption-key-here
APP_ENCRYPTION_KEY=your-very-strong-field-encryption-key-here
BACKUP_ENCRYPTION_KEY=your-very-strong-backup-encryption-key-here

# Adjust other settings as needed
BACKUP_INTERVAL_HOURS=24
BACKUP_RETENTION_DAYS=30
RATE_LIMIT_REQUESTS_PER_SECOND=10
```

## Usage

### Run the application
```bash
make run
```

### Run tests
```bash
make test
```

### Run security scan
```bash
make security-scan
```

### Create manual backup
From within the application, select option 6 from the main menu.

## Project Structure

```
secure-notes/
├── cmd/secure-notes/          # Application entry point
├── internal/
│   ├── audit/                 # Audit logging system
│   ├── backup/                # Backup management
│   ├── config/                # Configuration
│   ├── database/              # Database connection & migrations
│   ├── models/                # Data models
│   ├── ratelimit/             # Rate limiting
│   ├── repository/            # Data access layer
│   ├── security/              # Security utilities
│   └── service/               # Business logic
├── pkg/
│   ├── errors/                # Custom error types
│   └── validator/             # Input validation
└── scripts/                   # Setup & testing scripts
```

## Security Best Practices Demonstrated

1. ✅ **Never hardcode encryption keys** - Use environment variables
2. ✅ **Use prepared statements** - Prevent SQL injection
3. ✅ **Validate all input** - Sanitize and validate user input
4. ✅ **Hash passwords properly** - Use Argon2id with proper parameters
5. ✅ **Encrypt sensitive data** - Both database and field-level encryption
6. ✅ **Set secure file permissions** - 0600 for sensitive files
7. ✅ **Enable audit logging** - Track all security-relevant events
8. ✅ **Implement rate limiting** - Prevent abuse and DoS
9. ✅ **Use transactions** - Ensure data integrity
10. ✅ **Create encrypted backups** - Secure backup strategy

## Security Checklist

- [x] Database encrypted with SQLCipher
- [x] Field-level encryption for sensitive data
- [x] Password hashing with Argon2id
- [x] SQL injection prevention via prepared statements
- [x] Input validation and sanitization
- [x] Rate limiting implemented
- [x] Audit logging enabled
- [x] Secure file permissions (0600)
- [x] Encrypted backups
- [x] Account lockout mechanism
- [x] Session management
- [x] Error handling (no information leakage)

## License

MIT License

## Contributing

Pull requests welcome! Please ensure all security tests pass.

## Disclaimer

This is a demonstration project for educational purposes. For production use, consider additional security measures such as:
- Two-factor authentication
- Key rotation mechanisms
- Hardware security modules (HSM)
- Regular security audits
- Penetration testing