# Makefile for TonkitLab Borrow Application

.PHONY: help build-local build-aws up-localstack up-aws down-localstack down-aws logs-localstack logs-aws clean

# Default target
help:
	@echo "Available commands:"
	@echo "  build-local      - Build Docker image for local development"
	@echo "  build-aws        - Build Docker image for AWS deployment"
	@echo "  up-localstack    - Start application with LocalStack"
	@echo "  up-aws          - Start application with real AWS"
	@echo "  down-localstack  - Stop LocalStack environment"
	@echo "  down-aws        - Stop AWS environment"
	@echo "  logs-localstack  - Show logs for LocalStack environment"
	@echo "  logs-aws        - Show logs for AWS environment"
	@echo "  clean           - Remove all containers and images"
	@echo "  init-localstack  - Initialize LocalStack resources"

# Build commands
build-local:
	docker build -t tonkitlab-app:local .

build-aws:
	docker build -t tonkitlab-app:aws .

# LocalStack environment
up-localstack:
	@echo "Starting LocalStack environment..."
	docker-compose -f docker-compose.localstack.yml up -d
	@echo "Waiting for LocalStack to be ready..."
	@sleep 10
	@echo "Initializing LocalStack resources..."
	@docker exec localstack bash -c "cd /docker-entrypoint-initaws.d && chmod +x init-localstack.sh && ./init-localstack.sh"

down-localstack:
	docker-compose -f docker-compose.localstack.yml down

logs-localstack:
	docker-compose -f docker-compose.localstack.yml logs -f

# AWS environment
up-aws:
	@echo "Starting AWS environment..."
	@echo "Make sure your AWS credentials are properly configured!"
	docker-compose -f docker-compose.aws.yml up -d

down-aws:
	docker-compose -f docker-compose.aws.yml down

logs-aws:
	docker-compose -f docker-compose.aws.yml logs -f

# Utility commands
init-localstack:
	docker exec localstack bash -c "cd /docker-entrypoint-initaws.d && chmod +x init-localstack.sh && ./init-localstack.sh"

clean:
	docker-compose -f docker-compose.localstack.yml down -v --remove-orphans
	docker-compose -f docker-compose.aws.yml down -v --remove-orphans
	docker system prune -f
	docker volume prune -f

# Development commands
dev-localstack: build-local up-localstack
	@echo "Development environment with LocalStack is ready!"
	@echo "Application: http://localhost:5000"
	@echo "LocalStack Dashboard: http://localhost:4566"

dev-aws: build-aws up-aws
	@echo "Development environment with AWS is ready!"
	@echo "Application: http://localhost:5000"
