# Main Error Categories

## 1. OSError: [Errno 22] Invalid argument
This is the most frequent error in the target DNS server log, appearing hundreds of times.

**Cause:**
- The DNS server is being overwhelmed by the massive volume of spoofed DNS queries (20 attack threads generating random subdomain queries).
- The server is trying to send responses to spoofed IP addresses that don't exist or are unreachable.
- Socket operations fail when trying to send UDP responses to invalid/spoofed source addresses.
- Network stack cannot handle the high volume of concurrent socket operations.

## 2. OSError: [Errno 9] Bad file descriptor
This error appears later in the attack, indicating severe resource exhaustion.

**Cause:**
- File descriptor exhaustion due to too many open socket connections.
- The DNS server has run out of available file descriptors.
- System resource limits exceeded due to the DoS attack.
- Sockets are being closed/invalidated while still being referenced.

## 3. RuntimeError: can't start new thread

**Cause:**
- Thread pool exhaustion—the server cannot create new threads to handle incoming requests.
- The system has hit the maximum thread limit.
- Memory exhaustion preventing new thread creation.

# Why These Errors Occur

**DNS Random Subdomain Attack Mechanics:**
- **IP Spoofing:** The attack uses random source IP addresses for each query.
- **Random Subdomains:** Generates queries like abc123.example.com, xyz789.test.com.
- **High Volume:** 20 concurrent attack threads bombarding the server.
- **Cache Misses:** Random subdomains force the server to perform external DNS lookups.

**Server Overload Sequence:**
- **Initial Load:** Server starts processing legitimate queries normally.
- **Attack Begins:** Massive influx of spoofed random subdomain queries.

**Resource Exhaustion:**
- Socket descriptors exhausted trying to respond to invalid IPs.
- Thread pool saturated handling concurrent requests.
- Memory pressure from maintaining connection state.

**System Failure:** Server cannot process new requests or maintain existing connections.

# NXDOMAIN Flood Impact

The logs show hundreds of NXDOMAIN responses from upstream, indicating:
- The server is forwarding random subdomain queries to Google DNS (8.8.8.8).
- External DNS responds with NXDOMAIN (domain doesn't exist).
- Processing overhead for each failed lookup consumes server resources.
- Creates an amplification effect—one attack query triggers multiple upstream operations.

# DoS Attack Success Indicators

The simulation successfully demonstrates:
- **Service Degradation:** Legitimate clients experiencing slow responses.
- **Resource Exhaustion:** Server hitting system limits.
- **Attack Detection:** Monitoring thread detected response time degradation.
- **Complete Overwhelm:** Server eventually unable to process any requests.

# Mitigation Strategies

To prevent these errors:
- **Rate Limiting:** Implement per-IP query rate limits.
- **Input Validation:** Filter obviously invalid or random subdomain patterns.
- **Resource Limits:** Configure appropriate socket and thread pool limits.
- **DDoS Protection:** Deploy upstream filtering and traffic shaping.
- **Response Rate Limiting:** Limit responses to prevent amplification.

The errors demonstrate a successful DNS DoS attack that completely overwhelms the target server's ability to process legitimate DNS queries.