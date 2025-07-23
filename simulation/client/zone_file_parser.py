import random
from rich.table import Table
from rich import box
from logger import console


class ZoneParser:
    """DNS zone file parser and query generator"""

    def __init__(self, file_logger):
        self.file_logger = file_logger

    def _filter_zone_lines(self, content):
        """Filter valid lines from zone file content."""
        return [
            line.strip()
            for line in content.splitlines()
            if line.strip()
            and not line.strip().startswith("//")
            and not line.strip().startswith(";")
        ]

    def _parse_dns_record(self, line):
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

    def _display_parsed_records(self, names):
        """Display parsed records in a Rich table."""
        table = Table(title="🗂️ Parsed Zone Records", box=box.SIMPLE)
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="yellow")

        for rec_name, rtype in names:
            table.add_row(rec_name, rtype)
            self.file_logger.debug(f"ZONE_RECORD - {rec_name} {rtype}")

        console.print(table)

    def parse_zone_file(self, zone_path):
        """Parse zone file and return a list of (name, rdatatype) tuples."""
        names = []
        self.file_logger.info(f"ZONE_PARSE - Starting to parse zone file: {zone_path}")

        try:
            with open(zone_path, "r") as f:
                content = f.read()

            lines = self._filter_zone_lines(content)

            for line in lines:
                record = self._parse_dns_record(line)
                if record:
                    names.append(record)

            console.print(
                f"[green]✅ Parsed {len(names)} records from zone file[/green]"
            )
            self.file_logger.info(
                f"ZONE_PARSE - Successfully parsed {len(names)} records from zone file"
            )

            if names:
                self._display_parsed_records(names)

        except Exception as e:
            console.print(f"[red]❌ Failed to parse zone file {zone_path}: {e}[/red]")
            self.file_logger.error(
                f"ZONE_PARSE - Failed to parse zone file {zone_path}: {e}"
            )

        return names

    def generate_queries(self, zone_records, n=5):
        """Return a list of random queries from zone file, plus some popular/non-existing domains."""
        queries = []

        # Add records from zone file
        if zone_records:
            selected = random.sample(zone_records, min(n, len(zone_records)))
            queries.extend(selected)
            self.file_logger.info(
                f"QUERY_PREP - Added {len(selected)} queries from zone file"
            )

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
        self.file_logger.info(
            f"QUERY_PREP - Added {len(external_queries)} external queries, total: {len(queries)}"
        )

        return queries
