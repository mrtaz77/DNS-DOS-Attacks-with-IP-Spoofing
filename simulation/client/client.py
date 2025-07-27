import signal
import time
import random
import threading
from config import ClientConfig
from logger import ClientLogger, console
from metrics import Metrics
from zone_file_parser import ZoneParser
from query_handler import DNSQueryHandler
from response_handler import DisplayHandler
from plotting import PlottingEngine


class DNSClient:
    """Main DNS client orchestrator"""

    def __init__(self):
        self.running = True
        self.config = None
        self.logger_setup = None
        self.file_logger = None
        self.metrics = None
        self.zone_parser = None
        self.query_handler = None
        self.display = None
        self.queries = []
        self.plotting_engine = None
        self.duration = None
        self._duration_timer = None

        # Setup signal handler
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle interrupt signal"""
        console.print(
            "\n[bold red]🛑 Received interrupt. Exiting gracefully...[/bold red]"
        )
        if self.file_logger:
            self.file_logger.info(
                "SIGNAL - Received interrupt signal, exiting gracefully"
            )
        self.running = False

    def _duration_timeout(self):
        """Called when duration timer expires."""
        console.print(
            "\n[bold yellow]⏰ Duration expired. Stopping client...[/bold yellow]"
        )
        if self.file_logger:
            self.file_logger.info(
                "DURATION - Simulation duration expired, stopping client"
            )
        self.running = False

    def initialize(self):
        """Initialize all components"""
        # Load configuration
        self.config = ClientConfig.from_args()
        self.config.validate()

        # Setup logging
        self.logger_setup = ClientLogger(log_file=self.config.log)
        self.file_logger = self.logger_setup.get_file_logger()

        # Initialize components
        self.metrics = Metrics(self.file_logger)
        self.zone_parser = ZoneParser(self.file_logger)
        self.query_handler = DNSQueryHandler(
            self.file_logger,
            bind_ip=self.config.bind_ip,
            bind_port=self.config.bind_port,  # fixed: use correct config property
            use_cookies=self.config.use_cookies,
        )
        self.display = DisplayHandler(self.metrics, self.file_logger)
        self.plotting_engine = PlottingEngine(
            self.metrics, self.config.report_dir, self.file_logger
        )

        # Handle duration parameter (from CLI or config)
        self.duration = getattr(self.config, "duration", None)
        if self.duration and self.duration > 0:
            self._duration_timer = threading.Timer(
                self.duration, self._duration_timeout
            )
            self._duration_timer.daemon = True

    def setup_queries(self):
        """Setup DNS queries from zone file or defaults"""
        zone_records = []
        if self.config.zone:
            zone_records = self.zone_parser.parse_zone_file(self.config.zone)
            if not zone_records:
                console.print(
                    "[yellow]⚠️ No valid records found in zone file, using hardcoded domains[/yellow]"
                )
                self.file_logger.warning(
                    "ZONE_PARSE - No valid records found in zone file, using hardcoded domains"
                )
        else:
            console.print(
                "[blue]ℹ️ No zone file specified, using hardcoded domains[/blue]"
            )

        self.queries = self.zone_parser.generate_queries(zone_records, n=5)
        console.print(f"[green]✅ Prepared {len(self.queries)} queries[/green]")

    def test_connectivity(self):
        """Test server connectivity"""
        return self.query_handler.test_connectivity(
            self.config.server_ip, self.config.server_port
        )

    def handle_successful_response(self, qname, qtype, result, parsing_time):
        """Handle successful DNS response"""
        elapsed = result["elapsed"]
        self.metrics.total_response_time += elapsed

        if elapsed > 1.0:
            self.metrics.delayed += 1
            self.display.log_response(qname, qtype, result, "DELAYED", parsing_time)
        else:
            self.metrics.success += 1
            self.display.log_response(qname, qtype, result, "SUCCESS", parsing_time)

        return 0  # Reset consecutive failures

    def handle_failed_response(
        self,
        qname,
        qtype,
        result,
        consecutive_failures,
        max_consecutive_failures,
        parsing_time,
    ):
        """Handle failed DNS response"""
        if result["error"] == "TIMEOUT":
            self.metrics.failure += 1
            consecutive_failures += 1
            console.print(f"[red]⏰ TIMEOUT for {qname} ({qtype})[/red]")
            self.file_logger.warning(
                f"TIMEOUT - {qname} {qtype} (consecutive: {consecutive_failures})"
            )
            self.display.log_response(qname, qtype, result, "FAILURE", parsing_time)

            if consecutive_failures >= max_consecutive_failures:
                console.print(
                    f"[red]💀 Unable to connect to server after {max_consecutive_failures} consecutive timeouts. Exiting.[/red]"
                )
                self.file_logger.error(
                    f"SERVER_UNREACHABLE - {max_consecutive_failures} consecutive timeouts, exiting"
                )
                self.running = False
        else:
            console.print(
                f"[red]❌ ERROR for {qname} ({qtype}): {result['error']}[/red]"
            )
            self.file_logger.error(f"ERROR - {qname} {qtype}: {result['error']}")
            self.display.log_response(qname, qtype, result, "FAILURE", parsing_time)

        return consecutive_failures

    def run_query_loop(self):
        """Run the main DNS query loop"""
        consecutive_failures = 0
        max_consecutive_failures = 1000
        query_id = 0

        console.print("\n[bold]🚀 Starting DNS queries...[/bold]\n")
        self.file_logger.info("QUERY_START - Starting DNS query loop")

        # Start duration timer if set
        if self._duration_timer:
            self._duration_timer.start()

        while self.running:
            qname, qtype = random.choice(self.queries)
            query_id += 1
            self.metrics.sent += 1

            self.display.log_request(qname, qtype, query_id)

            try:
                result = self.query_handler.send_query(
                    self.config.server_ip,
                    self.config.server_port,
                    qname,
                    qtype,
                    self.config.timeout,
                )

                parsing_time = result.get("parsing_time", 0)
                if result["success"]:
                    consecutive_failures = self.handle_successful_response(
                        qname, qtype, result, parsing_time
                    )
                else:
                    consecutive_failures = self.handle_failed_response(
                        qname,
                        qtype,
                        result,
                        consecutive_failures,
                        max_consecutive_failures,
                        parsing_time,
                    )

            except Exception as e:
                console.print(f"[red]💥 Unexpected error: {e}[/red]")
                self.file_logger.error(f"UNEXPECTED_ERROR - {e}")

            if self.metrics.sent % 10 == 0:
                console.print("\n")
                self.metrics.log()
                console.print("\n")

            time.sleep(self.config.interval)

        # Cancel timer if still running
        if self._duration_timer:
            self._duration_timer.cancel()

    def run(self):
        """Main execution method"""
        try:
            self.initialize()
            self.display.log_startup_info(self.config)

            if not self.test_connectivity():
                console.print("[red]❌ Cannot connect to DNS server. Exiting.[/red]")
                return

            self.setup_queries()
            self.run_query_loop()

        finally:
            if self.display:
                self.display.show_summary()

            # Generate plots and metrics reports
            if self.plotting_engine:
                console.print(
                    "\n[bold blue]📊 Generating comprehensive analysis reports...[/bold blue]"
                )
                try:
                    self.plotting_engine.generate_all_reports()
                    console.print(
                        f"[green]✅ Analysis reports saved to: {self.config.report_dir}[/green]"
                    )
                except Exception as e:
                    console.print(f"[red]❌ Error generating reports: {e}[/red]")
                    if self.file_logger:
                        self.file_logger.error(f"PLOTTING_ERROR - {e}")


if __name__ == "__main__":
    client = DNSClient()
    client.run()
