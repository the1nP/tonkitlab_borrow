# TonkitLab Borrow - Docker Deployment

This guide explains how to run the TonkitLab Borrow application using Docker with two different configurations:

1. **LocalStack** - For local development with AWS services simulation
2. **AWS** - For production/staging with real AWS services

## Prerequisites

- Docker and Docker Compose installed
- Make (optional, for using Makefile commands)
- AWS CLI (for AWS environment)

## Quick Start

### Option 1: LocalStack Environment (Recommended for Development)

This option runs the application with LocalStack, which simulates AWS services locally.

```bash
# Using Makefile (recommended)
make dev-localstack

# Or using Docker Compose directly
docker-compose -f docker-compose.localstack.yml up -d
```

The application will be available at:
- **Application**: http://localhost:5000
- **LocalStack Dashboard**: http://localhost:4566

### Option 2: AWS Environment (Production/Staging)

This option connects to real AWS services.

1. **Configure AWS credentials** in `.env.aws`:
```bash
cp .env.aws .env.aws.local
# Edit .env.aws.local with your real AWS credentials
```

2. **Start the application**:
```bash
# Using Makefile
make dev-aws

# Or using Docker Compose directly
docker-compose -f docker-compose.aws.yml up -d
```

## Configuration Files

### Environment Files

#### `.env.localstack` - LocalStack Configuration
- Pre-configured for LocalStack
- Uses test credentials
- Points to LocalStack endpoints

#### `.env.aws` - AWS Configuration
- Template for real AWS configuration
- **Important**: Copy to `.env.aws.local` and fill in your real credentials
- Never commit real credentials to version control

### Docker Compose Files

#### `docker-compose.localstack.yml`
- Includes LocalStack service
- Automatically initializes AWS resources
- Good for development and testing

#### `docker-compose.aws.yml`
- Connects to real AWS services
- Requires valid AWS credentials
- For production/staging environments

## Available Commands (using Makefile)

```bash
# Development
make dev-localstack    # Start complete LocalStack environment
make dev-aws          # Start complete AWS environment

# Building
make build-local      # Build Docker image
make build-aws        # Build Docker image for AWS

# Management
make up-localstack    # Start LocalStack environment
make up-aws          # Start AWS environment
make down-localstack  # Stop LocalStack environment
make down-aws        # Stop AWS environment

# Monitoring
make logs-localstack  # View LocalStack logs
make logs-aws        # View AWS logs

# Cleanup
make clean           # Remove all containers and images
```

## AWS Resources Required

The application requires the following AWS resources:

### DynamoDB Tables
- `Equipment` - Store equipment information
- `BorrowReturnRecords` - Store borrow/return records

### S3 Buckets
- Profile images bucket (default: `tooltrack-profilepic`)
- Equipment images bucket (optional)

### Cognito
- User Pool for authentication
- User Pool Client

### Secrets Manager
- Secret containing application configuration
- Secret name: `equipment-app/config`

### IAM Permissions
Your AWS credentials need permissions for:
- DynamoDB (read/write)
- S3 (read/write)
- Cognito (user management)
- Secrets Manager (read)

## LocalStack Automatic Setup

When using LocalStack, the following resources are automatically created:

1. **S3 Buckets**:
   - `tooltrack-profilepic`
   - `equipment-images-bucket`

2. **DynamoDB Tables**:
   - `Equipment`
   - `BorrowReturnRecords`

3. **Cognito User Pool**:
   - Pool name: `equipment-app-pool`
   - Client with generated secret

4. **Secrets Manager**:
   - Secret: `equipment-app/config`
   - Contains application configuration

## Troubleshooting

### LocalStack Issues

1. **LocalStack not starting**:
   ```bash
   # Check Docker logs
   docker-compose -f docker-compose.localstack.yml logs localstack
   
   # Restart LocalStack
   make down-localstack
   make up-localstack
   ```

2. **Resources not created**:
   ```bash
   # Manually run initialization
   make init-localstack
   ```

### AWS Issues

1. **Authentication errors**:
   - Verify AWS credentials in `.env.aws`
   - Check IAM permissions
   - Ensure AWS CLI is configured

2. **Resource not found**:
   - Verify all required AWS resources exist
   - Check resource names in environment variables

### Application Issues

1. **Application not starting**:
   ```bash
   # Check application logs
   make logs-localstack  # or logs-aws
   
   # Rebuild image
   make build-local      # or build-aws
   ```

2. **Health check failures**:
   ```bash
   # Check if port 5000 is available
   netstat -tlnp | grep 5000
   ```

## Security Notes

- Never commit real AWS credentials to version control
- Use IAM roles in production instead of access keys when possible
- Regularly rotate AWS credentials
- Use AWS Secrets Manager for sensitive configuration in production

## Development Tips

1. **Use LocalStack for development** - it's faster and doesn't cost money
2. **Test with real AWS** before deploying to production
3. **Monitor logs** during development: `make logs-localstack`
4. **Clean up regularly** to free disk space: `make clean`

## Production Deployment

For production deployment:

1. Use `docker-compose.aws.yml` as a base
2. Configure proper AWS credentials (preferably IAM roles)
3. Use a reverse proxy (nginx) for SSL termination
4. Configure proper monitoring and logging
5. Use Docker secrets for sensitive data
6. Consider using AWS ECS or EKS for container orchestration
