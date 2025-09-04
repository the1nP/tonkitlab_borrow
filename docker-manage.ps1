# TonkitLab Borrow - Docker Management Script for Windows
# PowerShell script to manage Docker environments

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("localstack", "aws", "build", "clean", "logs", "help")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("up", "down", "restart")]
    [string]$Command = "up",
    
    [Parameter(Mandatory=$false)]
    [switch]$Rebuild
)

function Show-Help {
    Write-Host "TonkitLab Borrow - Docker Management Script" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage: .\docker-manage.ps1 -Action <action> [-Command <command>] [-Rebuild]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Actions:" -ForegroundColor Cyan
    Write-Host "  localstack   - Manage LocalStack environment"
    Write-Host "  aws          - Manage AWS environment"
    Write-Host "  build        - Build Docker images"
    Write-Host "  clean        - Clean up Docker resources"
    Write-Host "  logs         - Show logs"
    Write-Host "  help         - Show this help"
    Write-Host ""
    Write-Host "Commands (for localstack/aws):" -ForegroundColor Cyan
    Write-Host "  up          - Start environment (default)"
    Write-Host "  down        - Stop environment"
    Write-Host "  restart     - Restart environment"
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -Rebuild    - Force rebuild Docker image before starting"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\docker-manage.ps1 -Action localstack -Command up"
    Write-Host "  .\docker-manage.ps1 -Action localstack -Command restart -Rebuild"
    Write-Host "  .\docker-manage.ps1 -Action aws -Command down"
    Write-Host "  .\docker-manage.ps1 -Action build"
    Write-Host "  .\docker-manage.ps1 -Action logs"
}

function Build-Images {
    Write-Host "Building Docker images..." -ForegroundColor Green
    
    Write-Host "Building for LocalStack..." -ForegroundColor Yellow
    docker build -t tonkitlab-app:local .
    
    Write-Host "Building for AWS..." -ForegroundColor Yellow
    docker build -t tonkitlab-app:aws .
    
    Write-Host "Build completed!" -ForegroundColor Green
}

function Manage-LocalStack {
    param([string]$Cmd)
    
    switch ($Cmd) {
        "up" {
            Write-Host "Starting LocalStack Pro environment..." -ForegroundColor Green
            
            # Check if LOCALSTACK_API_KEY is set
            if (-not $env:LOCALSTACK_API_KEY) {
                Write-Host "Warning: LOCALSTACK_API_KEY is not set. Please set your LocalStack Pro API key." -ForegroundColor Yellow
                Write-Host "You can set it with: `$env:LOCALSTACK_API_KEY = 'your-api-key'" -ForegroundColor Yellow
            }
            
            if ($Rebuild) {
                Write-Host "Rebuilding Docker image..." -ForegroundColor Yellow
                docker-compose -f docker-compose.localstack.yml up -d --build
            } else {
                docker-compose -f docker-compose.localstack.yml up -d
            }
            
            Write-Host "Waiting for LocalStack Pro to be ready..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            
            Write-Host "Checking if LocalStack resources exist..." -ForegroundColor Yellow
            $tablesExist = docker exec localstack aws --endpoint-url=http://localhost:4566 dynamodb list-tables --query 'TableNames' --output text 2>$null
            
            if ($tablesExist -and $tablesExist.Contains("Equipment")) {
                Write-Host "Resources already exist, skipping initialization..." -ForegroundColor Green
            } else {
                Write-Host "Initializing LocalStack Pro resources..." -ForegroundColor Yellow
                docker exec localstack bash -c "cd /docker-entrypoint-initaws.d && chmod +x init-localstack.sh && ./init-localstack.sh"
            }
            
            Write-Host ""
            Write-Host "LocalStack Pro environment is ready!" -ForegroundColor Green
            Write-Host "Application: http://localhost:5000" -ForegroundColor Cyan
            Write-Host "LocalStack: http://localhost:4566" -ForegroundColor Cyan
            Write-Host "LocalStack Pro Dashboard: https://app.localstack.cloud" -ForegroundColor Cyan
        }
        "down" {
            Write-Host "Stopping LocalStack Pro environment..." -ForegroundColor Yellow
            docker-compose -f docker-compose.localstack.yml down
            Write-Host "LocalStack Pro environment stopped." -ForegroundColor Green
        }
        "restart" {
            Write-Host "Restarting LocalStack Pro environment..." -ForegroundColor Yellow
            docker-compose -f docker-compose.localstack.yml down
            Start-Sleep -Seconds 5
            
            if ($Rebuild) {
                Write-Host "Rebuilding Docker image..." -ForegroundColor Yellow
                docker-compose -f docker-compose.localstack.yml up -d --build
            } else {
                docker-compose -f docker-compose.localstack.yml up -d
            }
            
            Write-Host "Waiting for LocalStack Pro to be ready..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            
            Write-Host "Checking if LocalStack resources exist..." -ForegroundColor Yellow
            $tablesExist = docker exec localstack aws --endpoint-url=http://localhost:4566 dynamodb list-tables --query 'TableNames' --output text 2>$null
            
            if ($tablesExist -and $tablesExist.Contains("Equipment")) {
                Write-Host "Resources already exist, skipping initialization..." -ForegroundColor Green
            } else {
                Write-Host "Initializing LocalStack Pro resources..." -ForegroundColor Yellow
                docker exec localstack bash -c "cd /docker-entrypoint-initaws.d && chmod +x init-localstack.sh && ./init-localstack.sh"
            }
            
            Write-Host "LocalStack Pro environment restarted!" -ForegroundColor Green
        }
    }
}

function Manage-AWS {
    param([string]$Cmd)
    
    switch ($Cmd) {
        "up" {
            Write-Host "Starting AWS environment..." -ForegroundColor Green
            Write-Host "Make sure your AWS credentials are properly configured!" -ForegroundColor Yellow
            
            if (-not (Test-Path ".env.aws")) {
                Write-Host "Warning: .env.aws file not found. Using default configuration." -ForegroundColor Red
            }
            
            if ($Rebuild) {
                Write-Host "Rebuilding Docker image..." -ForegroundColor Yellow
                docker-compose -f docker-compose.aws.yml up -d --build
            } else {
                docker-compose -f docker-compose.aws.yml up -d
            }
            
            Write-Host ""
            Write-Host "AWS environment is ready!" -ForegroundColor Green
            Write-Host "Application: http://localhost:5000" -ForegroundColor Cyan
        }
        "down" {
            Write-Host "Stopping AWS environment..." -ForegroundColor Yellow
            docker-compose -f docker-compose.aws.yml down
            Write-Host "AWS environment stopped." -ForegroundColor Green
        }
        "restart" {
            Write-Host "Restarting AWS environment..." -ForegroundColor Yellow
            docker-compose -f docker-compose.aws.yml down
            Start-Sleep -Seconds 5
            
            if ($Rebuild) {
                Write-Host "Rebuilding Docker image..." -ForegroundColor Yellow
                docker-compose -f docker-compose.aws.yml up -d --build
            } else {
                docker-compose -f docker-compose.aws.yml up -d
            }
            Write-Host "AWS environment restarted!" -ForegroundColor Green
        }
    }
}

function Show-Logs {
    Write-Host "Select environment to show logs:" -ForegroundColor Yellow
    Write-Host "1. LocalStack"
    Write-Host "2. AWS"
    $choice = Read-Host "Enter choice (1 or 2)"
    
    switch ($choice) {
        "1" {
            Write-Host "Showing LocalStack logs..." -ForegroundColor Green
            docker-compose -f docker-compose.localstack.yml logs -f
        }
        "2" {
            Write-Host "Showing AWS logs..." -ForegroundColor Green
            docker-compose -f docker-compose.aws.yml logs -f
        }
        default {
            Write-Host "Invalid choice. Please enter 1 or 2." -ForegroundColor Red
        }
    }
}

function Clean-Docker {
    Write-Host "Cleaning up Docker resources..." -ForegroundColor Yellow
    
    Write-Host "Stopping all environments..." -ForegroundColor Yellow
    docker-compose -f docker-compose.localstack.yml down -v --remove-orphans
    docker-compose -f docker-compose.aws.yml down -v --remove-orphans
    
    Write-Host "Pruning Docker system..." -ForegroundColor Yellow
    docker system prune -f
    docker volume prune -f
    
    Write-Host "Cleanup completed!" -ForegroundColor Green
}

# Check if Docker is running
try {
    docker version | Out-Null
} catch {
    Write-Host "Error: Docker is not running or not installed." -ForegroundColor Red
    exit 1
}

# Check if docker-compose is available
try {
    docker-compose version | Out-Null
} catch {
    Write-Host "Error: docker-compose is not available." -ForegroundColor Red
    exit 1
}

# Main script logic
switch ($Action) {
    "help" {
        Show-Help
    }
    "build" {
        Build-Images
    }
    "localstack" {
        Manage-LocalStack -Cmd $Command
    }
    "aws" {
        Manage-AWS -Cmd $Command
    }
    "logs" {
        Show-Logs
    }
    "clean" {
        Clean-Docker
    }
    default {
        Write-Host "Invalid action. Use -Action help for usage information." -ForegroundColor Red
        exit 1
    }
}
