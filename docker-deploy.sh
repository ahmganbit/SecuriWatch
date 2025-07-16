#!/bin/bash
# SecurityWatch Pro - Docker Deployment Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command_exists docker; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command_exists docker-compose; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p data logs reports nginx/ssl
    
    # Set proper permissions
    chmod 755 data logs reports
    
    print_success "Directories created"
}

# Generate self-signed SSL certificate for development
generate_ssl_cert() {
    if [ ! -f "nginx/ssl/cert.pem" ] || [ ! -f "nginx/ssl/key.pem" ]; then
        print_status "Generating self-signed SSL certificate for development..."
        
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/key.pem \
            -out nginx/ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=SecurityWatch/CN=localhost" \
            >/dev/null 2>&1
        
        print_success "SSL certificate generated"
    else
        print_status "SSL certificate already exists"
    fi
}

# Build Docker images
build_images() {
    print_status "Building SecurityWatch Pro Docker image..."
    
    docker-compose build --no-cache
    
    print_success "Docker image built successfully"
}

# Deploy application
deploy_application() {
    local profile=${1:-""}
    
    if [ "$profile" = "production" ]; then
        print_status "Deploying SecurityWatch Pro in PRODUCTION mode..."
        docker-compose --profile production up -d
    else
        print_status "Deploying SecurityWatch Pro in DEVELOPMENT mode..."
        docker-compose up -d securitywatch-web securitywatch-monitor
    fi
    
    print_success "SecurityWatch Pro deployed successfully"
}

# Show deployment status
show_status() {
    print_status "Checking deployment status..."
    
    echo ""
    docker-compose ps
    echo ""
    
    # Wait for services to be ready
    print_status "Waiting for services to be ready..."
    sleep 10
    
    # Check if web service is responding
    if curl -f http://localhost:5000/api/stats >/dev/null 2>&1; then
        print_success "Web dashboard is responding"
        echo ""
        echo "🌐 SecurityWatch Pro Web Dashboard: http://localhost:5000"
        echo "📊 API Status Endpoint: http://localhost:5000/api/stats"
        echo ""
    else
        print_warning "Web dashboard is not responding yet. Please wait a moment and try again."
    fi
}

# Show logs
show_logs() {
    print_status "Showing recent logs..."
    docker-compose logs --tail=50
}

# Stop application
stop_application() {
    print_status "Stopping SecurityWatch Pro..."
    docker-compose down
    print_success "SecurityWatch Pro stopped"
}

# Clean up everything
cleanup() {
    print_status "Cleaning up SecurityWatch Pro deployment..."
    docker-compose down -v --remove-orphans
    docker system prune -f
    print_success "Cleanup completed"
}

# Main deployment function
main() {
    echo "🛡️ SecurityWatch Pro - Docker Deployment"
    echo "=========================================="
    
    case "${1:-deploy}" in
        "deploy")
            check_prerequisites
            create_directories
            generate_ssl_cert
            build_images
            deploy_application "${2:-}"
            show_status
            ;;
        "production")
            check_prerequisites
            create_directories
            generate_ssl_cert
            build_images
            deploy_application "production"
            show_status
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs
            ;;
        "stop")
            stop_application
            ;;
        "restart")
            stop_application
            sleep 2
            deploy_application "${2:-}"
            show_status
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [command] [options]"
            echo ""
            echo "Commands:"
            echo "  deploy          Deploy in development mode (default)"
            echo "  production      Deploy in production mode with Nginx"
            echo "  status          Show deployment status"
            echo "  logs            Show application logs"
            echo "  stop            Stop all services"
            echo "  restart         Restart all services"
            echo "  cleanup         Stop and remove all containers and volumes"
            echo "  help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 deploy                    # Deploy in development mode"
            echo "  $0 production                # Deploy in production mode"
            echo "  $0 status                    # Check status"
            echo "  $0 logs                      # View logs"
            ;;
        *)
            print_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
