# dns_server/servers/udp_server.py
import socket
import threading
import logging
import queue
import time
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional, Tuple, Any

class UDPServer:
    def __init__(self, handler, addr='0.0.0.0', port=53, max_workers=50, queue_size=1000):
        """
        Initialize UDP DNS Server with thread pool for better resource management
        
        Args:
            handler: DNS request handler
            addr: Server address to bind to
            port: Server port to bind to
            max_workers: Maximum number of worker threads (default: 50)
            queue_size: Maximum queue size for pending requests (default: 1000)
        """
        self.handler = handler
        self.addr = addr
        self.port = port
        self.max_workers = max_workers
        self.queue_size = queue_size
        
        # Create socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow immediate reuse of address after server restart
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set socket timeout to allow graceful shutdown
        self.sock.settimeout(1.0)
        self.sock.bind((addr, port))
        
        # Thread pool for processing requests
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="DNS-Worker"
        )
        
        # Statistics
        self.stats = {
            'requests_received': 0,
            'requests_processed': 0,
            'requests_dropped': 0,
            'queue_full_drops': 0,
            'active_threads': 0
        }
        self.stats_lock = threading.Lock()
        
        # Shutdown flag
        self.running = False
        
        logging.info("UDP DNS Server initialized on %s:%d (max_workers=%d, queue_size=%d)", 
                    addr, port, max_workers, queue_size)

    def serve(self):
        """
        Main server loop with improved error handling and resource management
        """
        self.running = True
        logging.info("Starting UDP DNS Server on %s:%d", self.addr, self.port)
        
        try:
            while self.running:
                try:
                    # Receive data with timeout to allow graceful shutdown
                    data, addr = self.sock.recvfrom(4096)
                    
                    with self.stats_lock:
                        self.stats['requests_received'] += 1
                    
                    # Submit request to thread pool with error handling
                    try:
                        future = self.executor.submit(self._process, data, addr)
                        # Don't wait for completion - fire and forget
                        future.add_done_callback(self._request_completed)
                        
                    except Exception as e:
                        # Thread pool is likely full or shutting down
                        with self.stats_lock:
                            self.stats['requests_dropped'] += 1
                            self.stats['queue_full_drops'] += 1
                        
                        logging.warning("Failed to submit request to thread pool: %s", e)
                        # Optionally send a server failure response
                        self._send_server_failure(data, addr)
                        
                except socket.timeout:
                    # Normal timeout, continue loop
                    continue
                    
                except socket.error as e:
                    if self.running:
                        logging.error("Socket error in UDP server: %s", e)
                        break
                    # Socket was closed during shutdown
                    
                except Exception as e:
                    logging.error("Unexpected error in UDP server: %s", e)
                    if self.running:
                        continue
                    else:
                        break
                        
        except KeyboardInterrupt:
            logging.info("UDP server interrupted by user")
        finally:
            self.shutdown()

    def _process(self, data: bytes, addr: Tuple[str, int]):
        """
        Process a single DNS request with improved error handling
        
        Args:
            data: Raw DNS request data
            addr: Client address tuple (ip, port)
        """
        client_ip = addr[0]
        
        try:
            with self.stats_lock:
                self.stats['active_threads'] += 1
            
            # Process the DNS request
            resp_wire, _ = self.handler.handle(data, addr)
            
            # Send response if we have one
            if resp_wire:
                try:
                    self.sock.sendto(resp_wire, addr)
                    with self.stats_lock:
                        self.stats['requests_processed'] += 1
                        
                except socket.error as e:
                    # Socket might be closed or network issue
                    if self.running:
                        logging.warning("Failed to send response to %s: %s", client_ip, e)
                    with self.stats_lock:
                        self.stats['requests_dropped'] += 1
                        
            else:
                # No response generated (rate limited, ACL denied, etc.)
                with self.stats_lock:
                    self.stats['requests_dropped'] += 1
                    
        except Exception as e:
            logging.error("Error processing request from %s: %s", client_ip, e)
            with self.stats_lock:
                self.stats['requests_dropped'] += 1
                
        finally:
            with self.stats_lock:
                self.stats['active_threads'] -= 1

    def _request_completed(self, future: Future):
        """
        Callback for completed request processing
        
        Args:
            future: Completed future from thread pool
        """
        try:
            # Check if there was an exception
            future.result()
        except Exception as e:
            logging.error("Request processing failed: %s", e)

    def _send_server_failure(self, data: bytes, addr: Tuple[str, int]):
        """
        Send a server failure response when we can't process the request
        
        Args:
            data: Original DNS request data
            addr: Client address
        """
        try:
            import dns.message
            import dns.rcode
            
            # Try to parse the original message to get the ID
            try:
                msg = dns.message.from_wire(data)
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.SERVFAIL)
                resp_wire = resp.to_wire()
                self.sock.sendto(resp_wire, addr)
                
            except Exception:
                # If we can't parse the message, just drop it
                pass
                
        except Exception as e:
            logging.debug("Failed to send server failure response: %s", e)

    def get_stats(self) -> dict:
        """
        Get current server statistics
        
        Returns:
            Dictionary with server statistics
        """
        with self.stats_lock:
            stats = self.stats.copy()
            
        # Add thread pool statistics
        stats.update({
            'thread_pool_active': len(self.executor._threads) if hasattr(self.executor, '_threads') else 0,
            'max_workers': self.max_workers,
            'queue_size': self.queue_size
        })
        
        return stats

    def shutdown(self):
        """
        Gracefully shutdown the server
        """
        logging.info("Shutting down UDP DNS Server...")
        self.running = False
        
        # Close socket
        try:
            self.sock.close()
        except Exception as e:
            logging.warning("Error closing socket: %s", e)
            
        # Shutdown thread pool
        try:
            self.executor.shutdown(wait=True, timeout=10)
            logging.info("Thread pool shutdown complete")
        except Exception as e:
            logging.warning("Error shutting down thread pool: %s", e)
            
        # Log final statistics
        stats = self.get_stats()
        logging.info("UDP Server final stats: %s", stats)
