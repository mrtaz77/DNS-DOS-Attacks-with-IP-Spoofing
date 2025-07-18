#!/bin/bash

# DNS Server Docker Management Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
logrestart_services() {
    local env="${1:-full}"
    log_info "Restarting $env environment..."
    case "$env" in
        "dev")
            $COMPOSE_CMD -f docker-compose.dev.yml -p "${PROJECT_NAME}-dev" restart
            ;;
        "prod")
            $COMPOSE_CMD -f docker-compose.prod.yml -p "${PROJECT_NAME}-prod" restart
            ;;
        "full"|*)
            $COMPOSE_CMD -f docker-compose.yml -p "${PROJECT_NAME}" restart
            ;;
    esac
    log_success "Services restarted"
}o -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
COMPOSE_FILE="docker-compose.yml"
PROJECT_NAME="dns-server"

show_help() {
    cat << EOF
DNS Server Docker Management Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
  dev         Start development environment (single server + Redis)
  prod        Start production environment (HA setup)
  full        Start full testing environment (all servers)
  stop        Stop all services
  restart     Restart services
  logs        Show logs for all services
  test        Run DNS tests against running services
  clean       Clean up containers and volumes
  build       Build Docker images
  status      Show service status

Examples:
  $0 dev                    # Start development environment
  $0 prod                   # Start production environment  
  $0 full                   # Start all servers for testing
  $0 logs dns-primary       # Show logs for primary server
  $0 test facebook.com      # Test DNS resolution
  $0 clean                  # Remove all containers and volumes

Environment Files:
  .env                      # Main environment configuration
  docker-compose.yml        # Full testing environment
  docker-compose.dev.yml    # Development environment
  docker-compose.prod.yml   # Production environment

EOF
}

check_requirements() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check for Docker Compose v2 first, then v1
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        log_error "Docker Compose is not installed"
        exit 1
    fi
}

setup_environment() {
    if [ ! -f .env ]; then
        log_info "Creating .env file from template..."
        cp .env.example .env
        log_warning "Please review and customize .env file"
    fi
    
    # Create logs directory
    mkdir -p logs
    
    # Generate certificates and keys if not exist
    if [ ! -f dns_server/certs/cert.pem ]; then
        log_info "Generating TLS certificates..."
        bash generate_certs.sh
    fi
    
    if [ ! -f dns_server/keys/tsig-key-*.key ]; then
        log_info "Generating TSIG keys..."
        bash generate_tsig_key.sh
    fi
}

start_development() {
    log_info "Starting development environment..."
    setup_environment
    $COMPOSE_CMD -f docker-compose.dev.yml -p "${PROJECT_NAME}-dev" up -d
    log_success "Development environment started!"
    log_info "DNS server available at: 127.0.0.1:5353 (UDP), 127.0.0.1:5354 (TCP)"
    log_info "Test with: dig @127.0.0.1 -p 5353 www.example.com A"
}

start_production() {
    log_info "Starting production environment..."
    setup_environment
    $COMPOSE_CMD -f docker-compose.prod.yml -p "${PROJECT_NAME}-prod" up -d
    log_success "Production environment started!"
    log_info "Primary DNS: 127.0.0.1:53, Secondary DNS: 127.0.0.1:54"
    log_info "DoT available on port 853"
}

start_full() {
    log_info "Starting full testing environment..."
    setup_environment
    $COMPOSE_CMD -f docker-compose.yml -p "${PROJECT_NAME}" up -d
    log_success "Full environment started!"
    echo ""
    log_info "Available DNS servers:"
    echo "  Primary:     127.0.0.1:5353 (UDP), 127.0.0.1:5354 (TCP)"
    echo "  Secondary 1: 127.0.0.1:7353 (UDP), 127.0.0.1:7354 (TCP)"
    echo "  Secondary 2: 127.0.0.1:8353 (UDP), 127.0.0.1:8354 (TCP)"
    echo "  Gateway:     127.0.0.1:9353 (UDP, load balanced)"
    echo "  Secure:      127.0.0.1:853 (DoT), 127.0.0.1:8443 (DoH)"
    echo "  Protected:   127.0.0.1:6353 (UDP, rate limited)"
    echo "  Redis:       127.0.0.1:6379"
}

stop_services() {
    log_info "Stopping all DNS services..."
    $COMPOSE_CMD -f docker-compose.yml -p "${PROJECT_NAME}" down 2>/dev/null || true
    $COMPOSE_CMD -f docker-compose.dev.yml -p "${PROJECT_NAME}-dev" down 2>/dev/null || true
    $COMPOSE_CMD -f docker-compose.prod.yml -p "${PROJECT_NAME}-prod" down 2>/dev/null || true
    log_success "All services stopped"
}

show_logs() {
    local service="$1"
    if [ -n "$service" ]; then
        $COMPOSE_CMD -f docker-compose.yml -p "${PROJECT_NAME}" logs -f "$service"
    else
        $COMPOSE_CMD -f docker-compose.yml -p "${PROJECT_NAME}" logs -f
    fi
}

start_production() {
    log_info "Starting production environment..."
    setup_environment
    docker compose -f docker-compose.prod.yml -p "${PROJECT_NAME}-prod" up -d
    log_success "Production environment started!"
    log_info "Primary DNS: 127.0.0.1:53, Secondary DNS: 127.0.0.1:54"
    log_info "DoT available on port 853"
}

start_full() {
    log_info "Starting full testing environment..."
    setup_environment
    docker compose -f docker-compose.yml -p "${PROJECT_NAME}" up -d
    log_success "Full environment started!"
    echo ""
    log_info "Available DNS servers:"
    echo "  Primary:     127.0.0.1:5353 (UDP), 127.0.0.1:5354 (TCP)"
    echo "  Secondary 1: 127.0.0.1:7353 (UDP), 127.0.0.1:7354 (TCP)"
    echo "  Secondary 2: 127.0.0.1:8353 (UDP), 127.0.0.1:8354 (TCP)"
    echo "  Gateway:     127.0.0.1:9353 (UDP, load balanced)"
    echo "  Secure:      127.0.0.1:853 (DoT), 127.0.0.1:8443 (DoH)"
    echo "  Protected:   127.0.0.1:6353 (UDP, rate limited)"
    echo "  Redis:       127.0.0.1:6379"
}

stop_services() {
    log_info "Stopping all DNS services..."
    docker compose -f docker-compose.yml -p "${PROJECT_NAME}" down 2>/dev/null || true
    docker compose -f docker-compose.dev.yml -p "${PROJECT_NAME}-dev" down 2>/dev/null || true
    docker compose -f docker-compose.prod.yml -p "${PROJECT_NAME}-prod" down 2>/dev/null || true
    log_success "All services stopped"
}

show_logs() {
    local service="$1"
    if [ -n "$service" ]; then
        docker compose -f docker-compose.yml -p "${PROJECT_NAME}" logs -f "$service"
    else
        docker compose -f docker-compose.yml -p "${PROJECT_NAME}" logs -f
    fi
}

run_tests() {
    local domain="${1:-www.example.com}"
    log_info "Testing DNS resolution for: $domain"
    echo ""
    
    # Test different servers
    servers=(
        "127.0.0.1:5353:Primary"
        "127.0.0.1:7353:Secondary-1"
        "127.0.0.1:8353:Secondary-2"
        "127.0.0.1:9353:Gateway"
        "127.0.0.1:6353:Protected"
    )
    
    for server_info in "${servers[@]}"; do
        IFS=':' read -r ip port name <<< "$server_info"
        echo -n "Testing $name ($ip:$port): "
        if timeout 3 dig @"$ip" -p "$port" "$domain" A +short +time=1 > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
        fi
    done
    
    echo ""
    log_info "Running cache test..."
    if [ -f test_dns_cache.py ]; then
        python3 test_dns_cache.py --simple
    else
        log_warning "test_dns_cache.py not found"
    fi
}

clean_environment() {
    log_warning "This will remove all DNS containers and volumes!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        stop_services
        docker system prune -f
        docker volume prune -f
        log_success "Environment cleaned"
    else
        log_info "Cancelled"
    fi
}

build_images() {
    log_info "Building DNS server Docker image..."
    docker build -t dns-server .
    log_success "Docker image built successfully"
}

show_status() {
    log_info "DNS Server Status:"
    echo ""
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(dns-|redis)" || log_warning "No DNS services running"
}

restart_services() {
    local env="${1:-full}"
    log_info "Restarting $env environment..."
    case "$env" in
        "dev")
            docker compose -f docker-compose.dev.yml -p "${PROJECT_NAME}-dev" restart
            ;;
        "prod")
            docker compose -f docker-compose.prod.yml -p "${PROJECT_NAME}-prod" restart
            ;;
        "full"|*)
            docker compose -f docker-compose.yml -p "${PROJECT_NAME}" restart
            ;;
    esac
    log_success "Services restarted"
}

# Main script
check_requirements

case "${1:-help}" in
    "dev")
        start_development
        ;;
    "prod")
        start_production
        ;;
    "full")
        start_full
        ;;
    "stop")
        stop_services
        ;;
    "restart")
        restart_services "$2"
        ;;
    "logs")
        show_logs "$2"
        ;;
    "test")
        run_tests "$2"
        ;;
    "clean")
        clean_environment
        ;;
    "build")
        build_images
        ;;
    "status")
        show_status
        ;;
    "help"|*)
        show_help
        ;;
esac
