#!/bin/bash

# Init script for LocalStack Pro to create required AWS resources

echo "Initializing LocalStack Pro resources..."

# Set LocalStack endpoint
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
ENDPOINT_URL=http://localhost:4566

# Wait for LocalStack to be ready
echo "Waiting for LocalStack Pro to be ready..."
while ! curl -s $ENDPOINT_URL/_localstack/health > /dev/null; do
    echo "Waiting for LocalStack Pro..."
    sleep 2
done
echo "LocalStack Pro is ready!"

# Create S3 bucket
echo "Creating S3 bucket..."
aws --endpoint-url=$ENDPOINT_URL s3 mb s3://tooltrack-profilepic
aws --endpoint-url=$ENDPOINT_URL s3 mb s3://equipment-images-bucket

# Create DynamoDB tables
echo "Creating DynamoDB tables..."

# Check if Equipment table exists
EQUIPMENT_EXISTS=$(aws --endpoint-url=$ENDPOINT_URL dynamodb list-tables --query 'TableNames' --output text | grep -c "Equipment" || true)

if [ "$EQUIPMENT_EXISTS" -eq 0 ]; then
    echo "Creating Equipment table..."
    aws --endpoint-url=$ENDPOINT_URL dynamodb create-table \
        --table-name Equipment \
        --attribute-definitions \
            AttributeName=equipment_id,AttributeType=S \
        --key-schema \
            AttributeName=equipment_id,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST
else
    echo "Equipment table already exists, skipping..."
fi

# Check if BorrowReturnRecords table exists
RECORDS_EXISTS=$(aws --endpoint-url=$ENDPOINT_URL dynamodb list-tables --query 'TableNames' --output text | grep -c "BorrowReturnRecords" || true)

if [ "$RECORDS_EXISTS" -eq 0 ]; then
    echo "Creating BorrowReturnRecords table..."
    aws --endpoint-url=$ENDPOINT_URL dynamodb create-table \
        --table-name BorrowReturnRecords \
        --attribute-definitions \
            AttributeName=record_id,AttributeType=S \
        --key-schema \
            AttributeName=record_id,KeyType=HASH \
        --billing-mode PAY_PER_REQUEST
else
    echo "BorrowReturnRecords table already exists, skipping..."
fi

# Create Cognito User Pool
echo "Creating Cognito User Pool..."

# Check if user pool exists
POOL_EXISTS=$(aws --endpoint-url=$ENDPOINT_URL cognito-idp list-user-pools --max-items 50 --query 'UserPools[?Name==`equipment-app-pool`].Id' --output text 2>/dev/null || true)

if [ -z "$POOL_EXISTS" ]; then
    echo "Creating new User Pool..."
    USER_POOL_OUTPUT=$(aws --endpoint-url=$ENDPOINT_URL cognito-idp create-user-pool \
        --pool-name "equipment-app-pool" \
        --policies "PasswordPolicy={MinimumLength=8,RequireUppercase=false,RequireLowercase=false,RequireNumbers=false,RequireSymbols=false}" \
        --query 'UserPool.Id' \
        --output text)
    
    echo "Created User Pool: $USER_POOL_OUTPUT"
    
    # Create User Pool Client
    USER_POOL_CLIENT_OUTPUT=$(aws --endpoint-url=$ENDPOINT_URL cognito-idp create-user-pool-client \
        --user-pool-id $USER_POOL_OUTPUT \
        --client-name "equipment-app-client" \
        --generate-secret \
        --query 'UserPoolClient.ClientId' \
        --output text)
    
    echo "Created User Pool Client: $USER_POOL_CLIENT_OUTPUT"
else
    echo "User Pool already exists: $POOL_EXISTS"
    USER_POOL_OUTPUT=$POOL_EXISTS
    
    # Get existing client ID
    USER_POOL_CLIENT_OUTPUT=$(aws --endpoint-url=$ENDPOINT_URL cognito-idp list-user-pool-clients \
        --user-pool-id $USER_POOL_OUTPUT \
        --query 'UserPoolClients[0].ClientId' \
        --output text)
    
    echo "Using existing User Pool Client: $USER_POOL_CLIENT_OUTPUT"
fi

# Create Secrets Manager secret
echo "Creating Secrets Manager secret..."

# Check if secret exists
SECRET_EXISTS=$(aws --endpoint-url=$ENDPOINT_URL secretsmanager list-secrets --query 'SecretList[?Name==`equipment-app/config`].Name' --output text 2>/dev/null || true)

if [ -z "$SECRET_EXISTS" ]; then
    echo "Creating new secret..."
    aws --endpoint-url=$ENDPOINT_URL secretsmanager create-secret \
        --name "equipment-app/config" \
        --secret-string '{
            "FLASK_SECRET_KEY": "localstack-pro-development-secret-key",
            "USER_POOL_ID": "'$USER_POOL_OUTPUT'",
            "APP_CLIENT_ID": "'$USER_POOL_CLIENT_OUTPUT'",
            "CLIENT_SECRET": "localstack-client-secret"
        }'
else
    echo "Secret already exists, updating..."
    aws --endpoint-url=$ENDPOINT_URL secretsmanager update-secret \
        --secret-id "equipment-app/config" \
        --secret-string '{
            "FLASK_SECRET_KEY": "localstack-pro-development-secret-key",
            "USER_POOL_ID": "'$USER_POOL_OUTPUT'",
            "APP_CLIENT_ID": "'$USER_POOL_CLIENT_OUTPUT'",
            "CLIENT_SECRET": "localstack-client-secret"
        }'
fi

echo "LocalStack Pro initialization completed!"
echo "User Pool ID: $USER_POOL_OUTPUT"
echo "App Client ID: $USER_POOL_CLIENT_OUTPUT"
