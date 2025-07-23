from rich.table import Table
from rich import box
from logger import console


class Metrics:
    """DNS client metrics collection and reporting"""

    def __init__(self, file_logger):
        self.sent = 0
        self.success = 0
        self.failure = 0  # Timeouts only
        self.delayed = 0  # Responses > 1 second
        self.total_response_time = 0.0
        self.requests_log = []
        self.responses_log = []
        self.file_logger = file_logger

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
        self.file_logger.info(
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
        self.file_logger.info(
            f"RESPONSE [{response_data['id']:04d}] {qname} {qtype} [{rcode}] {answers_count} answers {elapsed:.3f}s [{status}]"
        )

    def log(self):
        """Display metrics table"""
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
        self.file_logger.info(
            f"METRICS - Sent: {self.sent}, Success: {self.success} ({self.success*100/total:.2f}%), Failure: {self.failure} ({self.failure*100/total:.2f}%), Delayed: {self.delayed} ({self.delayed*100/total:.2f}%), Avg Time: {avg_response_time:.3f}s"
        )

    def get_summary(self):
        """Get metrics summary as dictionary"""
        total = self.sent if self.sent else 1
        avg_response_time = self.total_response_time / max(
            self.success + self.delayed, 1
        )

        return {
            "sent": self.sent,
            "success": self.success,
            "failure": self.failure,
            "delayed": self.delayed,
            "success_rate": self.success * 100 / total,
            "failure_rate": self.failure * 100 / total,
            "delayed_rate": self.delayed * 100 / total,
            "avg_response_time": avg_response_time,
        }
