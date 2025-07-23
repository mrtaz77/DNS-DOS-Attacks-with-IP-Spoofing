import socket
import time
import dns.message
import dns.query
import dns.rdataclass
import dns.exception


class DNSQueryHandler:
    """DNS query execution and response handling"""

    def __init__(self, file_logger):
        self.file_logger = file_logger

    def send_query(
        self, server, port, qname, qtype, tsig_client, timeout=10, use_tcp=False
    ):
        """Send DNS query using raw DNS packets"""
        try:
            # Create DNS query message
            query_msg = dns.message.make_query(qname, qtype, dns.rdataclass.IN)

            # Apply TSIG if enabled
            query_msg = tsig_client.sign_query(query_msg)

            # Log the query details
            self.file_logger.debug(
                f"DNS_QUERY - {qname} {qtype} to {server}:{port}"
            )

            start_time = time.time()

            try:
                if use_tcp:
                    # Use TCP for the query
                    response = dns.query.tcp(
                        query_msg, server, port=port, timeout=timeout
                    )
                else:
                    # Use UDP for the query
                    response = dns.query.udp(
                        query_msg, server, port=port, timeout=timeout
                    )

                elapsed = time.time() - start_time

                # Verify TSIG if enabled
                if not tsig_client.verify_response(response):
                    return {
                        "success": False,
                        "elapsed": elapsed,
                        "error": "TSIG_VERIFICATION_FAILED",
                        "output": "TSIG signature verification failed",
                    }

                # Parse response
                rcode = dns.rcode.to_text(response.rcode())
                answers_count = response.section_count("ANSWER")

                # Format response output
                output_lines = []
                for rrset in response.answer:
                    for rr in rrset:
                        output_lines.append(str(rr))

                output = "\n".join(output_lines) if output_lines else ""

                self.file_logger.debug(
                    f"DNS_RESPONSE - {rcode}, {answers_count} answers, {elapsed:.3f}s"
                )

                return {
                    "success": True,
                    "elapsed": elapsed,
                    "answers_count": answers_count,
                    "rcode": rcode,
                    "output": output,
                    "response": response,
                }

            except dns.exception.Timeout:
                elapsed = time.time() - start_time
                return {
                    "success": False,
                    "elapsed": elapsed,
                    "error": "TIMEOUT",
                    "output": "DNS query timeout",
                }
            except socket.error as e:
                elapsed = time.time() - start_time
                return {
                    "success": False,
                    "elapsed": elapsed,
                    "error": "NETWORK_ERROR",
                    "output": f"Network error: {e}",
                }

        except Exception as e:
            return {
                "success": False,
                "elapsed": 0,
                "error": "EXCEPTION",
                "output": str(e),
            }

    def test_connectivity(self, server, port, tsig_client):
        """Test basic connectivity using raw DNS packets"""
        try:
            from logger import console

            console.print(
                f"[yellow]🔍 Testing connectivity to {server}:{port}...[/yellow]"
            )
            self.file_logger.info(
                f"CONNECTIVITY_TEST - Testing connection to {server}:{port}"
            )

            result = self.send_query(
                server, port, "google.com.", "A", tsig_client, timeout=5
            )

            if result["success"]:
                console.print(
                    f"[green]✅ Connectivity test successful ({result['elapsed']:.3f}s)[/green]"
                )
                self.file_logger.info(
                    f"CONNECTIVITY_TEST - Success, response time: {result['elapsed']:.3f}s"
                )
                return True
            else:
                console.print(
                    f"[red]❌ Connectivity test failed: {result['error']}[/red]"
                )
                self.file_logger.error(f"CONNECTIVITY_TEST - Failed: {result['error']}")
                return False

        except Exception as e:
            console.print(f"[red]❌ Connectivity test failed: {e}[/red]")
            self.file_logger.error(f"CONNECTIVITY_TEST - Exception: {e}")
            return False
