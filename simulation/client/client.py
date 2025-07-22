import argparse
import subprocess
import json
import random
import time
import signal
import sys
import re
from pathlib import Path
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
import logging

# --- Rich Console setup ---
console = Console()

# --- Enhanced Logging setup with Rich and File ---
# Create a file logger for detailed logging
file_logger = logging.getLogger("CLIENT")
file_logger.setLevel(logging.DEBUG)

# Create file handler with detailed format
file_handler = logging.FileHandler("dns_client.log", mode="w")
file_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
file_handler.setFormatter(file_formatter)
file_logger.addHandler(file_handler)

# Enhanced Logging setup with Rich for console
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(console=console, rich_tracebacks=True),
    ],
)

logger = logging.getLogger("CLIENT")


# --- Metrics ---
class Metrics:
    def __init__(self):
        self.sent = 0
        self.success = 0
        self.failure = 0  # Timeouts only
        self.delayed = 0  # Responses > 1 second
        self.total_response_time = 0.0
        self.requests_log = []
        self.responses_log = []

    def add_request(self, qname, qtype, timestamp):
        """Log outgoing request"""
        request_data = {
            "timestamp": timestamp,
            "qname": qname,
            "qtype": qtype,
            "id": len(self.requests_log) + 1,
        }
        self.requests_log.append(request_data)

        # Log to file
        file_logger.info(
            f"REQUEST [{request_data['id']:04d}] {qname} {qtype} at {timestamp}"
        )

    def add_response(self, qname, qtype, rcode, elapsed, answers_count, status):
        """Log incoming response"""
        response_data = {
            "qname": qname,
            "qtype": qtype,
            "rcode": rcode,
            "elapsed": elapsed,
            "answers_count": answers_count,
            "status": status,
            "id": len(self.responses_log) + 1,
        }
        self.responses_log.append(response_data)

        # Log to file
        file_logger.info(
            f"RESPONSE [{response_data['id']:04d}] {qname} {qtype} [{rcode}] {answers_count} answers {elapsed:.3f}s [{status}]"
        )

    def log(self):
        total = self.sent if self.sent else 1
        avg_response_time = self.total_response_time / max(
            self.success + self.delayed, 1
        )

        # Create metrics table
        table = Table(title="📊 DNS Client Metrics", box=box.ROUNDED)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", style="magenta")
        table.add_column("Percentage", style="green")

        table.add_row("Requests Sent", str(self.sent), "100.00%")
        table.add_row("Success", str(self.success), f"{self.success*100/total:.2f}%")
        table.add_row(
            "Failure (Timeouts)", str(self.failure), f"{self.failure*100/total:.2f}%"
        )
        table.add_row(
            "Delayed (>1s)", str(self.delayed), f"{self.delayed*100/total:.2f}%"
        )
        table.add_row("Avg Response Time", f"{avg_response_time:.3f}s", "-")

        console.print(table)

        # Log metrics to file
        file_logger.info(
            f"METRICS - Sent: {self.sent}, Success: {self.success} ({self.success*100/total:.2f}%), Failure: {self.failure} ({self.failure*100/total:.2f}%), Delayed: {self.delayed} ({self.delayed*100/total:.2f}%), Avg Time: {avg_response_time:.3f}s"
        )


metrics = Metrics()
running = True


def signal_handler(sig, frame):
    global running
    console.print("\n[bold red]🛑 Received interrupt. Exiting gracefully...[/bold red]")
    file_logger.info("SIGNAL - Received interrupt signal, exiting gracefully")
    running = False


signal.signal(signal.SIGINT, signal_handler)


# --- Helper functions ---
def _filter_zone_lines(content):
    """Filter valid lines from zone file content."""
    return [
        line.strip()
        for line in content.splitlines()
        if line.strip()
        and not line.strip().startswith("//")
        and not line.strip().startswith(";")
    ]


def _parse_dns_record(line):
    """Parse a single DNS record line and return (name, type) tuple or None."""
    parts = line.split()
    if len(parts) < 3:
        return None
    
    name = parts[0]
    record_type = parts[1] if parts[1] in ["A", "CNAME", "MX", "TXT"] else "A"
    
    # Ensure name ends with dot
    if not name.endswith("."):
        name += "."
    
    return (name, record_type)


def _display_parsed_records(names):
    """Display parsed records in a Rich table."""
    table = Table(title="🗂️ Parsed Zone Records", box=box.SIMPLE)
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="yellow")
    
    for rec_name, rtype in names[:10]:
        table.add_row(rec_name, rtype)
        file_logger.debug(f"ZONE_RECORD - {rec_name} {rtype}")
    
    if len(names) > 10:
        table.add_row("...", "...")
        table.add_row(f"[dim]({len(names) - 10} more records)[/dim]", "")
    
    console.print(table)


def parse_zone_file(zone_path):
    """Parse zone file and return a list of (name, rdatatype) tuples."""
    names = []
    file_logger.info(f"ZONE_PARSE - Starting to parse zone file: {zone_path}")

    try:
        with open(zone_path, "r") as f:
            content = f.read()

        lines = _filter_zone_lines(content)
        
        for line in lines:
            record = _parse_dns_record(line)
            if record:
                names.append(record)

        console.print(f"[green]✅ Parsed {len(names)} records from zone file[/green]")
        file_logger.info(f"ZONE_PARSE - Successfully parsed {len(names)} records from zone file")

        if names:
            _display_parsed_records(names)

    except Exception as e:
        console.print(f"[red]❌ Failed to parse zone file {zone_path}: {e}[/red]")
        logger.error(f"Zone parsing error: {e}")
        file_logger.error(f"ZONE_PARSE - Failed to parse zone file {zone_path}: {e}")

    return names

def random_queries(zone_records, n=5):
    """Return a list of random queries from zone file, plus some popular/non-existing domains."""
    queries = []

    # Add records from zone file
    if zone_records:
        selected = random.sample(zone_records, min(n, len(zone_records)))
        queries.extend(selected)
        file_logger.info(f"QUERY_PREP - Added {len(selected)} queries from zone file")

    # Add some popular and non-existing domains
    external_queries = [
        ("google.com.", "A"),
        ("facebook.com.", "A"),
        ("nonexistentdomain12345.com.", "A"),
        ("example.com.", "A"),
        ("doesnotexist.example.com.", "A"),
        ("www.google.com.", "CNAME"),
    ]
    queries.extend(external_queries)
    file_logger.info(
        f"QUERY_PREP - Added {len(external_queries)} external queries, total: {len(queries)}"
    )

    return queries


def send_dig_query(server, port, qname, qtype, timeout=10):
    """Send DNS query using dig subprocess"""
    try:
        # Build dig command
        cmd = [
            "dig",
            f"@{server}",
            "-p",
            str(port),
            qname,
            qtype,
            "+time=" + str(round(timeout)),
            "+tries=1",
            "+short",
        ]

        file_logger.debug(f"COMMAND - {' '.join(cmd)}")

        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,  # Give extra time for subprocess
        )
        elapsed = time.time() - start_time

        # Parse dig output
        if result.returncode == 0:
            output = result.stdout.strip()
            answers_count = (
                len([line for line in output.split("\n") if line.strip()])
                if output
                else 0
            )

            return {
                "success": True,
                "elapsed": elapsed,
                "answers_count": answers_count,
                "rcode": "NOERROR",
                "output": output,
            }
        else:
            error_output = result.stderr.strip()

            # Parse error for timeout vs other errors
            if (
                "connection timed out" in error_output.lower()
                or "timeout" in error_output.lower()
            ):
                return {
                    "success": False,
                    "elapsed": elapsed,
                    "error": "TIMEOUT",
                    "output": error_output,
                }
            else:
                return {
                    "success": False,
                    "elapsed": elapsed,
                    "error": "ERROR",
                    "output": error_output,
                }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "elapsed": timeout,
            "error": "TIMEOUT",
            "output": "Subprocess timeout",
        }
    except Exception as e:
        return {"success": False, "elapsed": 0, "error": "EXCEPTION", "output": str(e)}


def log_request(qname, qtype, query_id):
    """Log outgoing DNS request with Rich formatting"""
    timestamp = time.strftime("%H:%M:%S")
    metrics.add_request(qname, qtype, timestamp)

    text = Text()
    text.append("📤 REQUEST ", style="bold blue")
    text.append(f"[{query_id:04d}] ", style="dim")
    text.append(f"{qname} ", style="cyan")
    text.append(f"{qtype}", style="yellow")

    console.print(text)


def log_response(qname, qtype, result, status):
    """Log incoming DNS response with Rich formatting"""
    elapsed = result.get("elapsed", 0)
    answers_count = result.get("answers_count", 0)
    rcode = result.get("rcode", "UNKNOWN")
    output = result.get("output", "")

    metrics.add_response(qname, qtype, rcode, elapsed, answers_count, status)

    # Console logging with Rich formatting
    text = Text()
    response_prefix = "📥 RESPONSE "
    if status == "SUCCESS":
        text.append(response_prefix, style="bold green")
    elif status == "DELAYED":
        text.append(response_prefix, style="bold yellow")
    else:
        text.append(response_prefix, style="bold red")

    text.append(f"{qname} ", style="cyan")
    text.append(f"{qtype} ", style="yellow")
    text.append(f"[{rcode}] ", style="magenta")
    text.append(f"{answers_count} answer{'s' if answers_count != 1 else ''} :", style="white")
    text.append(f"{output.strip().replace('\n', ' ')} ", style="bold green")
    text.append(f"({elapsed:.3f}s)", style="dim")

    console.print(text)

    # Log response content if available
    if output and output.strip():
        file_logger.info(f"RESPONSE_CONTENT - {qname} {qtype}: {output.strip().replace('\n',' ')}")

    # Log error details if it's a failure
    if status == "FAILURE" and "error" in result:
        console.print(f"  [red]Error: {result.get('error', 'Unknown error')}[/red]")
        file_logger.error(
            f"RESPONSE_ERROR - {qname} {qtype}: {result.get('error', 'Unknown error')}"
        )


def test_connectivity(server, port):
    """Test basic connectivity using dig"""
    try:
        console.print(f"[yellow]🔍 Testing connectivity to {server}:{port}...[/yellow]")
        file_logger.info(f"CONNECTIVITY_TEST - Testing connection to {server}:{port}")

        result = send_dig_query(server, port, "google.com.", "A", timeout=5)

        if result["success"]:
            console.print(
                f"[green]✅ Connectivity test successful ({result['elapsed']:.3f}s)[/green]"
            )
            file_logger.info(
                f"CONNECTIVITY_TEST - Success, response time: {result['elapsed']:.3f}s"
            )
            return True
        else:
            console.print(f"[red]❌ Connectivity test failed: {result['error']}[/red]")
            file_logger.error(f"CONNECTIVITY_TEST - Failed: {result['error']}")
            return False

    except Exception as e:
        console.print(f"[red]❌ Connectivity test failed: {e}[/red]")
        file_logger.error(f"CONNECTIVITY_TEST - Exception: {e}")
        return False

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="🌐 DNS Client using dig subprocess")
    parser.add_argument("--server", required=True, help="DNS server IP")
    parser.add_argument("--port", type=int, default=53, help="DNS server port")
    parser.add_argument("--zone", help="Path to zone file (optional)")
    parser.add_argument(
        "--interval", type=float, default=1.0, help="Interval between queries (seconds)"
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="Query timeout (seconds)"
    )
    return parser.parse_args()


def log_startup_info(args):
    """Log startup information and display banner."""
    file_logger.info(
        f"STARTUP - DNS Client starting with server: {args.server}:{args.port}"
    )
    file_logger.info(
        f"STARTUP - Configuration: Zone={args.zone}, Interval={args.interval}s, Timeout={args.timeout}s"
    )

    console.print(
        Panel.fit(
            "[bold blue]🌐 DNS Client Starting[/bold blue]\n"
            f"Server: {args.server}:{args.port}\n"
            f"Zone: {args.zone or 'None'}\n"
            f"Interval: {args.interval}s\n"
            f"Using: dig subprocess",
            title="Configuration",
            border_style="blue",
        )
    )


def setup_queries(zone_path):
    """Setup queries from zone file or defaults."""
    zone_records = []
    if zone_path:
        zone_records = parse_zone_file(zone_path)
        if not zone_records:
            console.print("[yellow]⚠️ No valid records found in zone file[/yellow]")
            file_logger.warning("ZONE_PARSE - No valid records found in zone file")

    queries = random_queries(zone_records, n=5)
    console.print(f"[green]✅ Prepared {len(queries)} queries[/green]")
    return queries


def handle_successful_response(qname, qtype, result):
    """Handle successful DNS response."""
    elapsed = result["elapsed"]
    metrics.total_response_time += elapsed

    file_logger.info(
        f"SUCCESS - {qname} {qtype} completed in {elapsed:.3f}s"
    )

    if elapsed > 1.0:
        metrics.delayed += 1
        log_response(qname, qtype, result, "DELAYED")
    else:
        metrics.success += 1
        log_response(qname, qtype, result, "SUCCESS")

    time.sleep(2)
    return 0  # Reset consecutive failures


def handle_failed_response(qname, qtype, result, consecutive_failures, max_consecutive_failures):
    """Handle failed DNS response."""
    global running
    
    if result["error"] == "TIMEOUT":
        metrics.failure += 1
        consecutive_failures += 1
        console.print(f"[red]⏰ TIMEOUT for {qname} ({qtype})[/red]")
        file_logger.warning(
            f"TIMEOUT - {qname} {qtype} (consecutive: {consecutive_failures})"
        )

        if consecutive_failures >= max_consecutive_failures:
            console.print(
                f"[red]💀 Unable to connect to server after {max_consecutive_failures} consecutive timeouts. Exiting.[/red]"
            )
            file_logger.error(
                f"SERVER_UNREACHABLE - {max_consecutive_failures} consecutive timeouts, exiting"
            )
            running = False
    else:
        console.print(
            f"[red]❌ ERROR for {qname} ({qtype}): {result['error']}[/red]"
        )
        file_logger.error(f"ERROR - {qname} {qtype}: {result['error']}")

    return consecutive_failures


def run_query_loop(server, port, timeout, interval, queries):
    """Run the main DNS query loop."""
    global running
    consecutive_failures = 0
    max_consecutive_failures = 10
    query_id = 0

    console.print("\n[bold]🚀 Starting DNS queries...[/bold]\n")
    file_logger.info("QUERY_START - Starting DNS query loop")

    while running:
        qname, qtype = random.choice(queries)
        query_id += 1
        metrics.sent += 1

        log_request(qname, qtype, query_id)

        try:
            result = send_dig_query(server, port, qname, qtype, timeout)

            if result["success"]:
                consecutive_failures = handle_successful_response(qname, qtype, result)
            else:
                consecutive_failures = handle_failed_response(
                    qname, qtype, result, consecutive_failures, max_consecutive_failures
                )

        except Exception as e:
            console.print(f"[red]💥 Unexpected error: {e}[/red]")
            file_logger.error(f"UNEXPECTED_ERROR - {e}")

        if metrics.sent % 10 == 0:
            console.print("\n")
            metrics.log()
            console.print("\n")

        time.sleep(interval)


def finalize_client():
    """Finalize client and log summary."""
    console.print("\n[yellow]🛑 Client stopped[/yellow]")
    file_logger.info("SHUTDOWN - DNS Client stopped")
    metrics.log()

    file_logger.info(
        f"FINAL_SUMMARY - Total requests: {metrics.sent}, Success: {metrics.success}, Failures: {metrics.failure}, Delayed: {metrics.delayed}"
    )


def main():
    args = parse_arguments()
    log_startup_info(args)

    if not test_connectivity(args.server, args.port):
        console.print("[red]❌ Cannot connect to DNS server. Exiting.[/red]")
        return

    queries = setup_queries(args.zone)
    run_query_loop(args.server, args.port, args.timeout, args.interval, queries)
    finalize_client()


if __name__ == "__main__":
    main()
