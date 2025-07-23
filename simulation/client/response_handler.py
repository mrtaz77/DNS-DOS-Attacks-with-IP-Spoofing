import time
from rich.text import Text
from rich.panel import Panel
from logger import console


class DisplayHandler:
    """Handle console output and response logging"""

    def __init__(self, metrics, file_logger):
        self.metrics = metrics
        self.file_logger = file_logger

    def log_startup_info(self, config):
        """Log startup information and display banner."""
        self.file_logger.info(
            f"STARTUP - DNS Client starting with server: {config.server}:{config.port}"
        )
        self.file_logger.info(
            f"STARTUP - Configuration: Zone={config.zone}, Interval={config.interval}s, Timeout={config.timeout}s"
        )

        tsig_status = "Enabled" if config.tsig_enabled else "Disabled"

        console.print(
            Panel.fit(
                "[bold blue]🌐 DNS Client Starting[/bold blue]\n"
                f"Server: {config.server}:{config.port}\n"
                f"Zone: {config.zone or 'None'}\n"
                f"Interval: {config.interval}s\n"
                f"Protocol: {config.protocol}\n"
                f"TSIG: {tsig_status}\n"
                f"Using: Raw DNS packets",
                title="Configuration",
                border_style="blue",
            )
        )

    def log_request(self, qname, qtype, query_id):
        """Log outgoing DNS request with Rich formatting"""
        timestamp = time.strftime("%H:%M:%S")
        self.metrics.add_request(qname, qtype, timestamp)

        text = Text()
        text.append("📤 REQUEST ", style="bold blue")
        text.append(f"[{query_id:04d}] ", style="dim")
        text.append(f"{qname} ", style="cyan")
        text.append(f"{qtype}", style="yellow")

        console.print(text)

    def log_response(self, qname, qtype, result, status):
        """Log incoming DNS response with Rich formatting"""
        elapsed = result.get("elapsed", 0)
        answers_count = result.get("answers_count", 0)
        rcode = result.get("rcode", "UNKNOWN")
        output = result.get("output", "")

        self.metrics.add_response(qname, qtype, rcode, elapsed, answers_count, status)

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
        text.append(
            f"{answers_count} answer{'s' if answers_count != 1 else ''}{' : ' if answers_count > 0 else ''}",
            style="white",
        )
        text.append(f"{output.strip().replace(chr(10), ' ')} ", style="bold green")
        text.append(f"({elapsed:.3f}s)", style="dim")

        console.print(text)

        # Log response content if available
        if output and output.strip():
            cleaned_output = output.strip().replace("\n", " ")
            self.file_logger.info(
                f"RESPONSE_CONTENT - {qname} {qtype}: {cleaned_output}"
            )

        # Log error details if it's a failure
        if status == "FAILURE" and "error" in result:
            console.print(f"  [red]Error: {result.get('error', 'Unknown error')}[/red]")
            self.file_logger.error(
                f"RESPONSE_ERROR - {qname} {qtype}: {result.get('error', 'Unknown error')}"
            )

    def show_summary(self):
        """Show final summary"""
        console.print("\n[yellow]🛑 Client stopped[/yellow]")
        self.file_logger.info("SHUTDOWN - DNS Client stopped")
        self.metrics.log()

        summary = self.metrics.get_summary()
        self.file_logger.info(
            f"FINAL_SUMMARY - Total requests: {summary['sent']}, Success: {summary['success']}, Failures: {summary['failure']}, Delayed: {summary['delayed']}"
        )
