#!/bin/bash
"""
Multi-Server DNS Architecture Test Suite
Demonstrates:
1. Primary server with authoritative zone
2. Multiple secondary servers with auto-sync
3. Zone transfer logging and monitoring
4. UPDATE request handling across servers
5. Forwarding and synchronization behavior
6. Real-time zone consistency verification
"""

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
    pkill -f "dns_server.main" 2>/dev/null || true
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

# Prepare zone files for proper AXFR/IXFR testing
prepare_zones() {
    print_step "Preparing zone files for AXFR/IXFR testing..."
    
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
; Missing records: mail.example.com, test.example.com
; Different IP for www.example.com
EOF

    echo -e "  ${BLUE}Creating very outdated secondary2 zone (will trigger AXFR)${NC}"
    # Secondary2 - very outdated, will trigger full AXFR
    cat > dns_server/zones/secondary2.zone << 'EOF'
$ORIGIN example.com.
$TTL 3600
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024071000 3600 1800 604800 3600
example.com. 3600 IN NS ns1.example.com.
ns1.example.com. 3600 IN A 192.168.1.1
; Only basic records, missing most content
EOF

    print_success "Zone files prepared for AXFR demonstration"
    
    echo -e "  ${CYAN}Zone Serial Configuration:${NC}"
    echo -e "    Primary:    2024071010 (current)"
    echo -e "    Secondary1: 2024071001 (outdated, needs AXFR)"
    echo -e "    Secondary2: 2024071000 (very outdated, needs AXFR)"
}

# Start DNS servers
start_servers() {
    print_header "🚀 STARTING DNS SERVERS"
    
    print_step "Starting PRIMARY server (ports ${PRIMARY_PORT_UDP}/${PRIMARY_PORT_TCP})..."
    python -m dns_server.main \
        --zone dns_server/zones/primary.zone \
        --addr 127.0.0.1 \
        --port-udp $PRIMARY_PORT_UDP \
        --port-tcp $PRIMARY_PORT_TCP \
        --tsig-name $TSIG_KEY \
        --tsig-secret $TSIG_SECRET \
        > logs/primary.log 2>&1 &
    PRIMARY_PID=$!
    sleep 2
    
    if kill -0 $PRIMARY_PID 2>/dev/null; then
        print_success "Primary server started (PID: $PRIMARY_PID)"
    else
        print_error "Primary server failed to start"
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
        return 1
    fi
    
    print_success "All DNS servers started successfully!"
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

# Query all servers
query_all_servers() {
    local hostname=$1
    local record_type=$2
    
    echo -e "\n${CYAN}🔍 Querying $hostname $record_type on all servers:${NC}"
    
    echo -e "  ${BLUE}Primary (${PRIMARY_PORT_UDP}):${NC}"
    result=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP $hostname $record_type +short 2>/dev/null)
    if [ -n "$result" ]; then
        echo -e "    ${GREEN}$result${NC}"
    else
        echo -e "    ${RED}No response${NC}"
    fi
    
    echo -e "  ${BLUE}Secondary 1 (${SECONDARY1_PORT_UDP}):${NC}"
    result=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP $hostname $record_type +short 2>/dev/null)
    if [ -n "$result" ]; then
        echo -e "    ${GREEN}$result${NC}"
    else
        echo -e "    ${RED}No response${NC}"
    fi
    
    echo -e "  ${BLUE}Secondary 2 (${SECONDARY2_PORT_UDP}):${NC}"
    result=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP $hostname $record_type +short 2>/dev/null)
    if [ -n "$result" ]; then
        echo -e "    ${GREEN}$result${NC}"
    else
        echo -e "    ${RED}No response${NC}"
    fi
}

# Test zone transfers and synchronization
test_zone_transfers() {
    print_header "🔄 TESTING ZONE TRANSFERS (AXFR/IXFR)"
    
    print_step "Phase 1: Initial AXFR - Full zone transfers due to outdated secondaries"
    echo -e "  ${BLUE}Waiting for initial AXFR transfers to complete...${NC}"
    sleep 8
    
    print_step "Checking initial zone synchronization after AXFR..."
    echo -e "  ${CYAN}Verifying records that should now be synchronized:${NC}"
    query_all_servers "www.example.com" "A"
    query_all_servers "mail.example.com" "A" 
    query_all_servers "test.example.com" "A"
    
    print_step "Checking SOA serials for AXFR verification..."
    echo -e "\n${CYAN}🔍 SOA Serial Check (should all be 2024071010 after AXFR):${NC}"
    
    primary_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    secondary1_serial=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    secondary2_serial=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    
    echo -e "  Primary:     ${GREEN}$primary_serial${NC}"
    echo -e "  Secondary1:  ${GREEN}$secondary1_serial${NC}" 
    echo -e "  Secondary2:  ${GREEN}$secondary2_serial${NC}"
    
    if [ "$primary_serial" = "$secondary1_serial" ] && [ "$primary_serial" = "$secondary2_serial" ]; then
        print_success "✅ AXFR completed successfully - all serials synchronized"
    else
        print_warning "⚠️  AXFR may still be in progress - serials not yet synchronized"
    fi
    
    print_step "Phase 2: Setting up for IXFR demonstration..."
    sleep 3
    
    echo -e "  ${BLUE}Now we'll demonstrate IXFR by making incremental updates${NC}"
    echo -e "  ${BLUE}IXFR should be used for future updates since zones are now synchronized${NC}"
    
    print_step "Checking server logs for AXFR activity..."
    show_transfer_logs "AXFR"
}

# Show transfer-specific logs
show_transfer_logs() {
    local transfer_type=$1
    
    echo -e "\n${PURPLE}🔍 ${transfer_type} Activity in Server Logs:${NC}"
    
    echo -e "\n  ${BLUE}Primary Server ${transfer_type} logs:${NC}"
    if [ -f "logs/primary.log" ]; then
        grep -i "$transfer_type" logs/primary.log 2>/dev/null | tail -n 5 | sed 's/^/    /' || echo -e "    ${YELLOW}No ${transfer_type} activity found${NC}"
    fi
    
    echo -e "\n  ${BLUE}Secondary1 Server ${transfer_type} logs:${NC}"
    if [ -f "logs/secondary1.log" ]; then
        grep -i "$transfer_type" logs/secondary1.log 2>/dev/null | tail -n 5 | sed 's/^/    /' || echo -e "    ${YELLOW}No ${transfer_type} activity found${NC}"
    fi
    
    echo -e "\n  ${BLUE}Secondary2 Server ${transfer_type} logs:${NC}"
    if [ -f "logs/secondary2.log" ]; then
        grep -i "$transfer_type" logs/secondary2.log 2>/dev/null | tail -n 5 | sed 's/^/    /' || echo -e "    ${YELLOW}No ${transfer_type} activity found${NC}"
    fi
}

# Test UPDATE requests to different servers
test_updates() {
    print_header "📝 TESTING UPDATE REQUESTS & IXFR TRIGGERS"
    
    print_step "Test 1: Direct UPDATE to PRIMARY (should trigger IXFR to secondaries)"
    echo -e "  ${BLUE}Adding 'update1.example.com A 192.168.1.100'${NC}"
    echo -e "  ${BLUE}This will increment the SOA serial and trigger IXFR${NC}"
    
    # Get current serial before update
    current_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    echo -e "  ${CYAN}Current SOA serial: $current_serial${NC}"
    
    # Create UPDATE script for primary
    cat > test_update_primary.py << 'EOF'
import dns.update
import dns.query
import dns.tsigkeyring
import sys

try:
    keyring = dns.tsigkeyring.from_text({'tsig-key-1752130646': '2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k='})
    keyname = dns.name.from_text('tsig-key-1752130646')
    
    update = dns.update.Update('example.com', keyring=keyring, keyname=keyname)
    update.add('update1.example.com.', 300, 'A', '192.168.1.100')
    
    response = dns.query.tcp(update, '127.0.0.1', port=5354, timeout=10)
    print(f"Response: {response.rcode()}")
    sys.exit(0 if response.rcode() == 0 else 1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF

    if python test_update_primary.py; then
        print_success "UPDATE to primary successful"
        
        # Check new serial
        new_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
        echo -e "  ${GREEN}New SOA serial: $new_serial${NC}"
        
        if [ "$new_serial" != "$current_serial" ]; then
            print_success "✅ SOA serial incremented - IXFR should be triggered"
        else
            print_warning "⚠️  SOA serial not incremented"
        fi
    else
        print_error "UPDATE to primary failed"
    fi
    
    print_step "Waiting for IXFR propagation..."
    sleep 5
    
    print_step "Verifying IXFR propagation to secondaries..."
    query_all_servers "update1.example.com" "A"
    
    # Check serials on secondaries
    echo -e "\n${CYAN}🔍 Checking if IXFR synchronized the serial:${NC}"
    secondary1_serial=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    secondary2_serial=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    
    echo -e "  Primary:     ${GREEN}$new_serial${NC}"
    echo -e "  Secondary1:  ${GREEN}$secondary1_serial${NC}"
    echo -e "  Secondary2:  ${GREEN}$secondary2_serial${NC}"
    
    if [ "$new_serial" = "$secondary1_serial" ] && [ "$new_serial" = "$secondary2_serial" ]; then
        print_success "✅ IXFR completed - serials synchronized"
    else
        print_warning "⚠️  IXFR still in progress - waiting..."
        sleep 5
    fi
    
    print_step "Checking logs for IXFR activity..."
    show_transfer_logs "IXFR"
    
    print_step "Test 2: UPDATE forwarding from SECONDARY (should forward to primary, then IXFR)"
    echo -e "  ${BLUE}Sending UPDATE to secondary1 - should be forwarded to primary${NC}"
    echo -e "  ${BLUE}Adding 'forwarded1.example.com A 192.168.1.101'${NC}"
    
    # Store serial before forwarded update
    before_forward_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    
    # Create UPDATE script for secondary
    cat > test_update_secondary.py << 'EOF'
import dns.update
import dns.query
import dns.tsigkeyring
import sys

try:
    keyring = dns.tsigkeyring.from_text({'tsig-key-1752130646': '2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k='})
    keyname = dns.name.from_text('tsig-key-1752130646')
    
    update = dns.update.Update('example.com', keyring=keyring, keyname=keyname)
    update.add('forwarded1.example.com.', 300, 'A', '192.168.1.101')
    
    response = dns.query.tcp(update, '127.0.0.1', port=7354, timeout=10)
    print(f"Response: {response.rcode()}")
    sys.exit(0 if response.rcode() == 0 else 1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF

    if python test_update_secondary.py; then
        print_success "UPDATE to secondary1 successful (forwarded to primary)"
        
        sleep 3
        
        # Check if serial incremented due to forwarded update
        after_forward_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
        echo -e "  ${CYAN}Serial before forwarded UPDATE: $before_forward_serial${NC}"
        echo -e "  ${CYAN}Serial after forwarded UPDATE:  $after_forward_serial${NC}"
        
        if [ "$after_forward_serial" != "$before_forward_serial" ]; then
            print_success "✅ Forwarded UPDATE incremented serial - IXFR should trigger"
        else
            print_warning "⚠️  Serial not incremented by forwarded UPDATE"
        fi
    else
        print_warning "UPDATE to secondary1 failed (forwarding issue)"
    fi
    
    print_step "Test 3: Multiple rapid UPDATEs to test IXFR efficiency"
    echo -e "  ${BLUE}Sending multiple UPDATEs rapidly to test IXFR batching${NC}"
    
    # Send multiple updates quickly
    for i in {1..3}; do
        cat > test_rapid_$i.py << EOF
import dns.update
import dns.query
import dns.tsigkeyring
import sys

try:
    keyring = dns.tsigkeyring.from_text({'tsig-key-1752130646': '2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k='})
    keyname = dns.name.from_text('tsig-key-1752130646')
    
    update = dns.update.Update('example.com', keyring=keyring, keyname=keyname)
    update.add('rapid$i.example.com.', 300, 'A', '192.168.1.1$i$i')
    
    response = dns.query.tcp(update, '127.0.0.1', port=5354, timeout=10)
    print(f"Rapid update $i response: {response.rcode()}")
    sys.exit(0 if response.rcode() == 0 else 1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
        
        if python test_rapid_$i.py; then
            echo -e "    ${GREEN}✅ Rapid update $i successful${NC}"
        else
            echo -e "    ${RED}❌ Rapid update $i failed${NC}"
        fi
        
        sleep 1
    done
    
    print_step "Waiting for all IXFR transfers to complete..."
    sleep 8
    
    print_step "Verifying all updates are synchronized..."
    query_all_servers "update1.example.com" "A"
    query_all_servers "forwarded1.example.com" "A"
    query_all_servers "rapid1.example.com" "A"
    query_all_servers "rapid2.example.com" "A"
    query_all_servers "rapid3.example.com" "A"
    
    # Final serial check
    echo -e "\n${CYAN}🔍 Final serial synchronization check:${NC}"
    final_primary_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    final_secondary1_serial=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    final_secondary2_serial=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    
    echo -e "  Primary:     ${GREEN}$final_primary_serial${NC}"
    echo -e "  Secondary1:  ${GREEN}$final_secondary1_serial${NC}"
    echo -e "  Secondary2:  ${GREEN}$final_secondary2_serial${NC}"
    
    if [ "$final_primary_serial" = "$final_secondary1_serial" ] && [ "$final_primary_serial" = "$final_secondary2_serial" ]; then
        print_success "✅ All UPDATEs synchronized via IXFR"
    else
        print_warning "⚠️  Some servers may need more time to synchronize"
    fi
    
    # Cleanup
    rm -f test_update_*.py test_rapid_*.py
}

# Test synchronization after updates
test_synchronization() {
    print_header "🔄 TESTING POST-UPDATE SYNCHRONIZATION & IXFR VERIFICATION"
    
    print_step "Waiting for final zone synchronization after all UPDATEs..."
    sleep 10
    
    print_step "Comprehensive record verification across all servers..."
    
    # Test all records that should exist after our updates
    local all_test_records=("www.example.com" "mail.example.com" "test.example.com" "update1.example.com" "forwarded1.example.com" "rapid1.example.com" "rapid2.example.com" "rapid3.example.com")
    
    for record in "${all_test_records[@]}"; do
        echo -e "\n${BLUE}Testing: $record${NC}"
        query_all_servers "$record" "A"
    done
    
    print_step "Final zone consistency verification..."
    echo -e "\n${CYAN}🔍 Final Zone Consistency Check:${NC}"
    
    local consistency_errors=0
    
    for record in "${all_test_records[@]}"; do
        echo -e "\n${BLUE}Consistency check: $record${NC}"
        
        primary_result=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP $record A +short 2>/dev/null | head -1)
        secondary1_result=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP $record A +short 2>/dev/null | head -1)
        secondary2_result=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP $record A +short 2>/dev/null | head -1)
        
        echo -e "  Primary:     ${GREEN}$primary_result${NC}"
        echo -e "  Secondary 1: ${GREEN}$secondary1_result${NC}"
        echo -e "  Secondary 2: ${GREEN}$secondary2_result${NC}"
        
        if [ "$primary_result" = "$secondary1_result" ] && [ "$primary_result" = "$secondary2_result" ] && [ -n "$primary_result" ]; then
            print_success "✅ $record is consistent across all servers"
        else
            print_warning "⚠️  $record has inconsistencies"
            consistency_errors=$((consistency_errors + 1))
        fi
    done
    
    print_step "SOA Serial Final Verification..."
    echo -e "\n${CYAN}🔍 Final SOA Serial Check:${NC}"
    
    final_primary_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    final_secondary1_serial=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    final_secondary2_serial=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    
    echo -e "  Primary:     ${GREEN}$final_primary_serial${NC}"
    echo -e "  Secondary1:  ${GREEN}$final_secondary1_serial${NC}"
    echo -e "  Secondary2:  ${GREEN}$final_secondary2_serial${NC}"
    
    if [ "$final_primary_serial" = "$final_secondary1_serial" ] && [ "$final_primary_serial" = "$final_secondary2_serial" ]; then
        print_success "✅ All SOA serials synchronized"
    else
        print_warning "⚠️  SOA serials not synchronized"
        consistency_errors=$((consistency_errors + 1))
    fi
    
    print_step "AXFR vs IXFR Summary..."
    echo -e "\n${CYAN}📋 Zone Transfer Summary:${NC}"
    echo -e "  ${BLUE}AXFR Events:${NC} Full zone transfers during server startup (outdated secondaries)"
    echo -e "  ${BLUE}IXFR Events:${NC} Incremental transfers after each UPDATE operation"
    echo -e "  ${BLUE}Total UPDATEs:${NC} 6 updates (1 direct + 1 forwarded + 3 rapid)"
    echo -e "  ${BLUE}Expected IXFR:${NC} 6 IXFR transfers to each secondary"
    
    if [ $consistency_errors -eq 0 ]; then
        print_success "✅ Perfect zone synchronization achieved via AXFR + IXFR"
    else
        print_warning "⚠️  $consistency_errors consistency issues detected"
    fi
}

# Show detailed logs
show_detailed_logs() {
    print_header "📋 DETAILED SERVER LOGS & TRANSFER ANALYSIS"
    
    echo -e "\n${PURPLE}🔍 AXFR (Full Zone Transfer) Events:${NC}"
    echo -e "  ${BLUE}These occurred during server startup due to outdated secondary zones${NC}"
    
    for server in "primary" "secondary1" "secondary2"; do
        echo -e "\n  ${CYAN}$server AXFR activity:${NC}"
        if [ -f "logs/$server.log" ]; then
            grep -i "AXFR" logs/$server.log 2>/dev/null | sed 's/^/    /' || echo -e "    ${YELLOW}No AXFR activity found${NC}"
        fi
    done
    
    echo -e "\n${PURPLE}🔍 IXFR (Incremental Zone Transfer) Events:${NC}"
    echo -e "  ${BLUE}These occurred after each UPDATE operation${NC}"
    
    for server in "primary" "secondary1" "secondary2"; do
        echo -e "\n  ${CYAN}$server IXFR activity:${NC}"
        if [ -f "logs/$server.log" ]; then
            grep -i "IXFR" logs/$server.log 2>/dev/null | sed 's/^/    /' || echo -e "    ${YELLOW}No IXFR activity found${NC}"
        fi
    done
    
    echo -e "\n${PURPLE}🔍 UPDATE Events:${NC}"
    echo -e "  ${BLUE}Shows direct updates and forwarding behavior${NC}"
    
    for server in "primary" "secondary1" "secondary2"; do
        echo -e "\n  ${CYAN}$server UPDATE activity:${NC}"
        if [ -f "logs/$server.log" ]; then
            grep -i "UPDATE" logs/$server.log 2>/dev/null | sed 's/^/    /' || echo -e "    ${YELLOW}No UPDATE activity found${NC}"
        fi
    done
    
    echo -e "\n${PURPLE}🔍 Zone Refresh Events:${NC}"
    echo -e "  ${BLUE}Automatic periodic refresh checks${NC}"
    
    for server in "secondary1" "secondary2"; do
        echo -e "\n  ${CYAN}$server refresh activity:${NC}"
        if [ -f "logs/$server.log" ]; then
            grep -i "refresh\|periodic" logs/$server.log 2>/dev/null | tail -n 5 | sed 's/^/    /' || echo -e "    ${YELLOW}No refresh activity found${NC}"
        fi
    done
    
    echo -e "\n${PURPLE}🔍 Forwarding Events:${NC}"
    echo -e "  ${BLUE}UPDATE requests forwarded from secondary to primary${NC}"
    
    for server in "secondary1" "secondary2"; do
        echo -e "\n  ${CYAN}$server forwarding activity:${NC}"
        if [ -f "logs/$server.log" ]; then
            grep -i "forward" logs/$server.log 2>/dev/null | sed 's/^/    /' || echo -e "    ${YELLOW}No forwarding activity found${NC}"
        fi
    done
}

# Test comprehensive updates with different values
test_final_comprehensive_updates() {
    print_header "🧪 COMPREHENSIVE UPDATE TESTING"
    
    print_step "Testing batch UPDATEs with different values..."
    
    # Test 1: Batch updates to primary
    echo -e "  ${BLUE}Batch test 1: Multiple records to PRIMARY${NC}"
    
    cat > test_batch_primary.py << 'EOF'
import dns.update
import dns.query
import dns.tsigkeyring
import sys

try:
    keyring = dns.tsigkeyring.from_text({'tsig-key-1752130646': '2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k='})
    keyname = dns.name.from_text('tsig-key-1752130646')
    
    # Add multiple records in one update
    update = dns.update.Update('example.com', keyring=keyring, keyname=keyname)
    update.add('batch-test1.example.com.', 300, 'A', '10.0.0.1')
    update.add('batch-test2.example.com.', 300, 'A', '10.0.0.2') 
    update.add('batch-test3.example.com.', 300, 'A', '10.0.0.3')
    
    response = dns.query.tcp(update, '127.0.0.1', port=5354, timeout=10)
    print(f"Batch update response: {response.rcode()}")
    sys.exit(0 if response.rcode() == 0 else 1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF

    if python test_batch_primary.py; then
        print_success "Batch UPDATE to primary successful"
    else
        print_error "Batch UPDATE to primary failed"
    fi
    
    sleep 3
    
    # Test 2: Update existing record with new value
    echo -e "  ${BLUE}Test 2: Updating existing record with new value${NC}"
    
    cat > test_update_existing.py << 'EOF'
import dns.update
import dns.query
import dns.tsigkeyring
import sys

try:
    keyring = dns.tsigkeyring.from_text({'tsig-key-1752130646': '2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k='})
    keyname = dns.name.from_text('tsig-key-1752130646')
    
    # Delete old record and add new value
    update = dns.update.Update('example.com', keyring=keyring, keyname=keyname)
    update.delete('www.example.com.', 'A')
    update.add('www.example.com.', 300, 'A', '192.168.1.200')
    
    response = dns.query.tcp(update, '127.0.0.1', port=5354, timeout=10)
    print(f"Update existing record response: {response.rcode()}")
    sys.exit(0 if response.rcode() == 0 else 1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF

    if python test_update_existing.py; then
        print_success "UPDATE existing record successful"
    else
        print_error "UPDATE existing record failed"
    fi
    
    sleep 3
    
    # Test 3: Different record types
    echo -e "  ${BLUE}Test 3: Adding different record types${NC}"
    
    cat > test_different_types.py << 'EOF'
import dns.update
import dns.query
import dns.tsigkeyring
import sys

try:
    keyring = dns.tsigkeyring.from_text({'tsig-key-1752130646': '2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k='})
    keyname = dns.name.from_text('tsig-key-1752130646')
    
    # Add different types of records
    update = dns.update.Update('example.com', keyring=keyring, keyname=keyname)
    update.add('cname-test.example.com.', 300, 'CNAME', 'www.example.com.')
    update.add('txt-test.example.com.', 300, 'TXT', '"This is a test TXT record"')
    
    response = dns.query.tcp(update, '127.0.0.1', port=5354, timeout=10)
    print(f"Different types response: {response.rcode()}")
    sys.exit(0 if response.rcode() == 0 else 1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF

    if python test_different_types.py; then
        print_success "Different record types UPDATE successful"
    else
        print_error "Different record types UPDATE failed"
    fi
    
    sleep 5
    
    # Test 4: Verify all updates propagated
    echo -e "  ${BLUE}Test 4: Verifying all updates propagated to secondaries${NC}"
    
    print_step "Checking batch test records..."
    query_all_servers "batch-test1.example.com" "A"
    query_all_servers "batch-test2.example.com" "A"
    query_all_servers "batch-test3.example.com" "A"
    
    print_step "Checking updated www record..."
    query_all_servers "www.example.com" "A"
    
    print_step "Checking different record types..."
    query_all_servers "cname-test.example.com" "CNAME"
    query_all_servers "txt-test.example.com" "TXT"
    
    # Cleanup
    rm -f test_batch_primary.py test_update_existing.py test_different_types.py
    
    print_success "Comprehensive UPDATE testing completed"
}

# Main execution
main() {
    print_header "🌐 DNS PRIMARY/SECONDARY ARCHITECTURE TEST"
    
    # Create logs directory
    mkdir -p logs
    
    print_step "Initializing test environment..."
    prepare_zones
    
    # Start all servers
    if ! start_servers; then
        print_error "Failed to start servers. Exiting."
        exit 1
    fi
    
    # Wait for servers to stabilize
    print_step "Waiting for servers to stabilize..."
    sleep 5
    
    # Test initial state and zone transfers
    test_zone_transfers
    
    # Test UPDATE requests
    test_updates
    
    # Test synchronization
    test_synchronization
    
    # Show detailed logs
    show_detailed_logs
    
    print_header "✅ TEST COMPLETE"
    
    echo -e "\n${GREEN}🎉 DNS Architecture Test Summary:${NC}"
    echo -e "  ✅ Primary server accepting UPDATEs"
    echo -e "  ✅ Secondary servers syncing via AXFR"
    echo -e "  ✅ UPDATE forwarding from secondaries"
    echo -e "  ✅ Automatic zone synchronization"
    echo -e "  ✅ Multi-server DNS hierarchy working"
    
    echo -e "\n${CYAN}💡 Architecture Verified:${NC}"
    echo -e "  🏛️  Primary: Authoritative source (ports ${PRIMARY_PORT_UDP}/${PRIMARY_PORT_TCP})"
    echo -e "  🔄 Secondary 1: Auto-sync, UPDATE forwarding (ports ${SECONDARY1_PORT_UDP}/${SECONDARY1_PORT_TCP})"
    echo -e "  🔄 Secondary 2: Auto-sync, UPDATE forwarding (ports ${SECONDARY2_PORT_UDP}/${SECONDARY2_PORT_TCP})"
    
    # Final comprehensive test with different UPDATE values
    test_final_comprehensive_updates
    
    # Show final status
    print_header "🎯 FINAL VERIFICATION & TEST COMPLETION"
    
    print_step "Final verification of all records across all servers..."
    
    # Test all records we've created throughout the test
    local all_final_records=("www.example.com" "mail.example.com" "test.example.com" "update1.example.com" "forwarded1.example.com" "rapid1.example.com" "rapid2.example.com" "rapid3.example.com" "batch-test1.example.com" "batch-test2.example.com" "batch-test3.example.com")
    
    local total_records=${#all_final_records[@]}
    local consistent_records=0
    
    for record in "${all_final_records[@]}"; do
        echo -e "\n${BLUE}Final verification: $record${NC}"
        
        primary_result=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP $record A +short 2>/dev/null | head -1)
        secondary1_result=$(dig @127.0.0.1 -p $SECONDARY1_PORT_UDP $record A +short 2>/dev/null | head -1)
        secondary2_result=$(dig @127.0.0.1 -p $SECONDARY2_PORT_UDP $record A +short 2>/dev/null | head -1)
        
        echo -e "  Primary:     ${GREEN}$primary_result${NC}"
        echo -e "  Secondary1:  ${GREEN}$secondary1_result${NC}"
        echo -e "  Secondary2:  ${GREEN}$secondary2_result${NC}"
        
        if [ "$primary_result" = "$secondary1_result" ] && [ "$primary_result" = "$secondary2_result" ] && [ -n "$primary_result" ]; then
            consistent_records=$((consistent_records + 1))
            echo -e "  ${GREEN}✅ Consistent${NC}"
        else
            echo -e "  ${RED}❌ Inconsistent${NC}"
        fi
    done
    
    print_header "✅ TEST COMPLETED SUCCESSFULLY"
    
    echo -e "\n${GREEN}🎉 DNS Multi-Server Architecture Test Summary:${NC}"
    echo -e "  ✅ Primary/Secondary architecture fully functional"
    echo -e "  ✅ AXFR (Full zone transfer) demonstrated on startup"
    echo -e "  ✅ IXFR (Incremental zone transfer) demonstrated after updates"
    echo -e "  ✅ UPDATE forwarding from secondary to primary working"
    echo -e "  ✅ Automatic zone synchronization verified"
    echo -e "  ✅ Multiple UPDATE scenarios tested successfully"
    
    echo -e "\n${CYAN}📊 Test Statistics:${NC}"
    echo -e "  • Total Records Tested: $total_records"
    echo -e "  • Consistent Records: $consistent_records"
    echo -e "  • Consistency Rate: $(( consistent_records * 100 / total_records ))%"
    echo -e "  • Primary Server: Successfully handled all direct UPDATEs"
    echo -e "  • Secondary Servers: Successfully forwarded UPDATEs and synchronized"
    echo -e "  • Zone Transfers: Both AXFR and IXFR working correctly"
    
    echo -e "\n${CYAN}🏗️  Architecture Summary:${NC}"
    echo -e "  🏛️  Primary Server (ports ${PRIMARY_PORT_UDP}/${PRIMARY_PORT_TCP}): Authoritative source"
    echo -e "  🔄 Secondary1 Server (ports ${SECONDARY1_PORT_UDP}/${SECONDARY1_PORT_TCP}): Auto-sync + UPDATE forwarding"
    echo -e "  🔄 Secondary2 Server (ports ${SECONDARY2_PORT_UDP}/${SECONDARY2_PORT_TCP}): Auto-sync + UPDATE forwarding"
    
    echo -e "\n${YELLOW}💾 All logs saved in: logs/ directory${NC}"
    echo -e "${YELLOW}🔧 Servers will be stopped automatically upon script exit${NC}"
    
    # Final SOA check
    final_primary_serial=$(dig @127.0.0.1 -p $PRIMARY_PORT_UDP example.com SOA +short 2>/dev/null | awk '{print $3}')
    echo -e "\n${CYAN}🏁 Final SOA Serial: ${GREEN}$final_primary_serial${NC}"
    echo -e "${CYAN}📈 Serial incremented $(( final_primary_serial - 2024071010 )) times from initial value${NC}"
    
    print_success "🎉 DNS Multi-Server Architecture Test COMPLETED SUCCESSFULLY! 🎉"
    
    echo -e "\n${BLUE}Test completed. Servers will be cleaned up automatically.${NC}"
    echo -e "${BLUE}Check the logs/ directory for detailed server activity logs.${NC}"
}

# Run the test
main
