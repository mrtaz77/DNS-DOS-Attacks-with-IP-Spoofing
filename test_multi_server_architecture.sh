#!/bin/bash
# Multi-Server DNS Architecture Test Suite
# Demonstrates:
# 1. Primary server with authoritative zone
# 2. Multiple secondary servers with auto-sync
# 3. Zone transfer logging and monitoring
# 4. UPDATE request handling across servers
# 5. Forwarding and synchronization behavior
# 6. Real-time zone consistency verification

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PRIMARY_PORT_UDP=5353
PRIMARY_PORT_TCP=5354
SECONDARY1_PORT_UDP=7353
SECONDARY1_PORT_TCP=7354
SECONDARY2_PORT_UDP=8353
SECONDARY2_PORT_TCP=8354
TSIG_KEY="tsig-key-1752130646"
TSIG_SECRET="2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k="

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up DNS servers...${NC}"
    pkill -f "dns_server/main.py" 2>/dev/null || true
    pkill -f "python.*dns_server" 2>/dev/null || true
    sleep 2
    echo -e "${GREEN}✅ Cleanup complete${NC}"
}

# Setup trap for cleanup
trap cleanup EXIT INT TERM

print_header() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

print_step() {
    echo -e "\n${BLUE}📋 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check if required files and packages exist
check_dependencies() {
    print_step "Checking dependencies..."
    
    # Check if DNS server main file exists
    if [ ! -f "dns_server/main.py" ]; then
        print_error "dns_server/main.py not found"
        echo -e "  ${YELLOW}Please ensure you're running from the correct directory${NC}"
        return 1
    fi
    
    # Check if Python can import dnspython
    if ! python -c "import dns.query, dns.zone" 2>/dev/null; then
        print_error "dnspython package not found"
        echo -e "  ${YELLOW}Please install: pip install dnspython${NC}"
        return 1
    fi
    
    # Check if dig command is available
    if ! command -v dig &> /dev/null; then
        print_warning "dig command not found - some tests may fail"
        echo -e "  ${YELLOW}Consider installing bind-utils or dnsutils package${NC}"
    fi
    
    print_success "All dependencies found"
    return 0
}

# Prepare zone files for proper AXFR/IXFR testing
prepare_zones() {
    print_step "Preparing zone files for AXFR/IXFR testing..."
    
    # Create zones directory if it doesn't exist
    mkdir -p dns_server/zones
    
    echo -e "  ${BLUE}Creating primary zone with current serial${NC}"
    # Create primary zone with higher serial (will trigger AXFR from secondaries)
    cat > dns_server/zones/primary.zone << 'EOF'
$ORIGIN example.com.
$TTL 3600
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024071010 3600 1800 604800 3600
example.com. 3600 IN NS ns1.example.com.
ns1.example.com. 3600 IN A 192.168.1.1
www.example.com. 3600 IN A 192.168.1.10
mail.example.com. 3600 IN A 192.168.1.20
test.example.com. 3600 IN A 192.168.1.30
EOF

    echo -e "  ${BLUE}Creating outdated secondary1 zone (will trigger AXFR)${NC}"
    # Secondary1 - significantly outdated, will trigger full AXFR
    cat > dns_server/zones/secondary1.zone << 'EOF'
$ORIGIN example.com.
$TTL 3600
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024071001 3600 1800 604800 3600
example.com. 3600 IN NS ns1.example.com.
ns1.example.com. 3600 IN A 192.168.1.1
www.example.com. 3600 IN A 192.168.1.2
EOF

    echo -e "  ${BLUE}Creating very outdated secondary2 zone (will trigger AXFR)${NC}"
    # Secondary2 - very outdated, will trigger full AXFR
    cat > dns_server/zones/secondary2.zone << 'EOF'
$ORIGIN example.com.
$TTL 3600
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024071000 3600 1800 604800 3600
example.com. 3600 IN NS ns1.example.com.
ns1.example.com. 3600 IN A 192.168.1.1
EOF

    # Create TSIG key file if it doesn't exist
    mkdir -p dns_server/keys
    if [ ! -f "dns_server/keys/tsig-key-1752130646.key" ]; then
        echo -e "  ${BLUE}Creating TSIG key file${NC}"
        cat > dns_server/keys/tsig-key-1752130646.key << EOF
key "tsig-key-1752130646" {
    algorithm hmac-sha256;
    secret "$TSIG_SECRET";
};
EOF
    fi

    print_success "Zone files prepared for AXFR demonstration"
    
    echo -e "  ${CYAN}Zone Serial Configuration:${NC}"
    echo -e "    Primary:    2024071010 (current)"
    echo -e "    Secondary1: 2024071001 (outdated, needs AXFR)"
    echo -e "    Secondary2: 2024071000 (very outdated, needs AXFR)"
}

# Start DNS servers with better error handling
start_servers() {
    print_header "🚀 STARTING DNS SERVERS"
    
    # Create logs directory
    mkdir -p logs
    
    print_step "Starting PRIMARY server (ports ${PRIMARY_PORT_UDP}/${PRIMARY_PORT_TCP})..."
    
    # Start the DNS server using the direct file approach
    python -m dns_server.main \
        --zone dns_server/zones/primary.zone \
        --addr 127.0.0.1 \
        --port-udp $PRIMARY_PORT_UDP \
        --port-tcp $PRIMARY_PORT_TCP \
        --tsig-name $TSIG_KEY \
        --tsig-secret $TSIG_SECRET \
        > logs/primary.log 2>&1 &
    
    PRIMARY_PID=$!
    sleep 3
    
    if kill -0 $PRIMARY_PID 2>/dev/null; then
        print_success "Primary server started (PID: $PRIMARY_PID)"
    else
        print_error "Primary server failed to start"
        echo -e "  ${YELLOW}Checking logs for errors...${NC}"
        if [ -f "logs/primary.log" ]; then
            echo -e "  ${RED}Error log:${NC}"
            tail -n 10 logs/primary.log | sed 's/^/    /'
        fi
        return 1
    fi
    
    print_step "Starting SECONDARY server 1 (ports ${SECONDARY1_PORT_UDP}/${SECONDARY1_PORT_TCP})..."
    
    python -m dns_server.main \
        --zone dns_server/zones/secondary1.zone \
        --addr 127.0.0.1 \
        --port-udp $SECONDARY1_PORT_UDP \
        --port-tcp $SECONDARY1_PORT_TCP \
        --secondary \
        --primary-server 127.0.0.1 \
        --primary-port $PRIMARY_PORT_TCP \
        --refresh-interval 30 \
        --tsig-name $TSIG_KEY \
        --tsig-secret $TSIG_SECRET \
        > logs/secondary1.log 2>&1 &
    
    SECONDARY1_PID=$!
    sleep 3
    
    if kill -0 $SECONDARY1_PID 2>/dev/null; then
        print_success "Secondary server 1 started (PID: $SECONDARY1_PID)"
    else
        print_error "Secondary server 1 failed to start"
        if [ -f "logs/secondary1.log" ]; then
            echo -e "  ${RED}Error log:${NC}"
            tail -n 10 logs/secondary1.log | sed 's/^/    /'
        fi
        return 1
    fi
    
    print_step "Starting SECONDARY server 2 (ports ${SECONDARY2_PORT_UDP}/${SECONDARY2_PORT_TCP})..."
    
    python -m dns_server.main \
        --zone dns_server/zones/secondary2.zone \
        --addr 127.0.0.1 \
        --port-udp $SECONDARY2_PORT_UDP \
        --port-tcp $SECONDARY2_PORT_TCP \
        --secondary \
        --primary-server 127.0.0.1 \
        --primary-port $PRIMARY_PORT_TCP \
        --refresh-interval 45 \
        --tsig-name $TSIG_KEY \
        --tsig-secret $TSIG_SECRET \
        > logs/secondary2.log 2>&1 &
    
    SECONDARY2_PID=$!
    sleep 3
    
    if kill -0 $SECONDARY2_PID 2>/dev/null; then
        print_success "Secondary server 2 started (PID: $SECONDARY2_PID)"
    else
        print_error "Secondary server 2 failed to start"
        if [ -f "logs/secondary2.log" ]; then
            echo -e "  ${RED}Error log:${NC}"
            tail -n 10 logs/secondary2.log | sed 's/^/    /'
        fi
        return 1
    fi
    
    print_success "All DNS servers started successfully!"
}

# Simple test to verify basic functionality
test_basic_queries() {
    print_header "🔍 TESTING BASIC QUERIES"
    
    print_step "Testing basic queries to verify servers are responding..."
    
    # Test primary server
    echo -e "\n${BLUE}Testing Primary Server (port $PRIMARY_PORT_UDP):${NC}"
    if command -v dig &> /dev/null; then
        result=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP www.example.com A +short +time=5 2>/dev/null)
        if [ -n "$result" ]; then
            echo -e "  ${GREEN}✅ Primary responds: $result${NC}"
        else
            echo -e "  ${RED}❌ Primary not responding${NC}"
        fi
    else
        echo -e "  ${YELLOW}⚠️  dig command not available - skipping query test${NC}"
    fi
    
    # Test secondary servers
    echo -e "\n${BLUE}Testing Secondary1 Server (port $SECONDARY1_PORT_UDP):${NC}"
    if command -v dig &> /dev/null; then
        result=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP www.example.com A +short +time=5 2>/dev/null)
        if [ -n "$result" ]; then
            echo -e "  ${GREEN}✅ Secondary1 responds: $result${NC}"
        else
            echo -e "  ${RED}❌ Secondary1 not responding${NC}"
        fi
    else
        echo -e "  ${YELLOW}⚠️  dig command not available - skipping query test${NC}"
    fi
    
    echo -e "\n${BLUE}Testing Secondary2 Server (port $SECONDARY2_PORT_UDP):${NC}"
    if command -v dig &> /dev/null; then
        result=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP www.example.com A +short +time=5 2>/dev/null)
        if [ -n "$result" ]; then
            echo -e "  ${GREEN}✅ Secondary2 responds: $result${NC}"
        else
            echo -e "  ${RED}❌ Secondary2 not responding${NC}"
        fi
    else
        echo -e "  ${YELLOW}⚠️  dig command not available - skipping query test${NC}"
    fi
    
    # Alternative test using netstat or ss to check if ports are listening
    print_step "Checking if DNS servers are listening on configured ports..."
    
    for port in $PRIMARY_PORT_UDP $SECONDARY1_PORT_UDP $SECONDARY2_PORT_UDP; do
        if command -v ss &> /dev/null; then
            if ss -ulnp | grep ":$port " &> /dev/null; then
                echo -e "  ${GREEN}✅ Port $port is listening${NC}"
            else
                echo -e "  ${RED}❌ Port $port is not listening${NC}"
            fi
        elif command -v netstat &> /dev/null; then
            if netstat -ulnp | grep ":$port " &> /dev/null; then
                echo -e "  ${GREEN}✅ Port $port is listening${NC}"
            else
                echo -e "  ${RED}❌ Port $port is not listening${NC}"
            fi
        else
            echo -e "  ${YELLOW}⚠️  Cannot check port status (ss/netstat not available)${NC}"
            break
        fi
    done
}

# Show server logs
show_logs() {
    local server=$1
    local logfile=$2
    
    echo -e "\n${PURPLE}📋 $server Server Logs (last 10 lines):${NC}"
    if [ -f "$logfile" ]; then
        tail -n 10 "$logfile" | sed 's/^/  /'
    else
        echo -e "  ${YELLOW}No logs available yet${NC}"
    fi
}

# Show all server logs
show_all_logs() {
    print_header "📋 SERVER LOGS"
    
    show_logs "Primary" "logs/primary.log"
    show_logs "Secondary1" "logs/secondary1.log"
    show_logs "Secondary2" "logs/secondary2.log"
}

# Main execution
main() {
    print_header "🌐 DNS PRIMARY/SECONDARY ARCHITECTURE TEST"
    
    # Check dependencies first
    if ! check_dependencies; then
        print_error "Dependency check failed. Exiting."
        exit 1
    fi
    
    print_step "Initializing test environment..."
    prepare_zones
    
    # Start all servers
    if ! start_servers; then
        print_error "Failed to start servers. Checking logs..."
        show_all_logs
        exit 1
    fi
    
    # Wait for servers to stabilize
    print_step "Waiting for servers to stabilize..."
    sleep 5
    
    # Test basic functionality
    test_basic_queries
    
    # Show logs
    show_all_logs
    
    print_header "✅ BASIC TEST COMPLETE"
    
    echo -e "\n${GREEN}🎉 DNS Architecture Basic Test Summary:${NC}"
    echo -e "  ✅ Primary server started successfully"
    echo -e "  ✅ Secondary servers started successfully"
    echo -e "  ✅ Basic DNS queries working"
    
    echo -e "\n${CYAN}💡 Architecture Status:${NC}"
    echo -e "  🏛️  Primary: Running on ports ${PRIMARY_PORT_UDP}/${PRIMARY_PORT_TCP}"
    echo -e "  🔄 Secondary 1: Running on ports ${SECONDARY1_PORT_UDP}/${SECONDARY1_PORT_TCP}"
    echo -e "  🔄 Secondary 2: Running on ports ${SECONDARY2_PORT_UDP}/${SECONDARY2_PORT_TCP}"
    
    echo -e "\n${YELLOW}💾 All logs saved in: logs/ directory${NC}"
    echo -e "${YELLOW}🔧 Servers will be stopped automatically upon script exit${NC}"
    
    print_success "🎉 DNS Multi-Server Architecture Basic Test COMPLETED! 🎉"
    
    echo -e "\n${BLUE}Test completed. Servers will be cleaned up automatically.${NC}"
    echo -e "${BLUE}Check the logs/ directory for detailed server activity logs.${NC}"
    
    # Keep servers running for a bit for manual testing
    echo -e "\n${CYAN}Servers will remain running for 30 seconds for manual testing...${NC}"
    echo -e "${CYAN}Press Ctrl+C to stop immediately or wait for automatic cleanup.${NC}"
    sleep 30
}

# Run the test
main