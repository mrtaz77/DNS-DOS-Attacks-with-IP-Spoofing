# dns_server/metrics.py
import threading

class MetricsCollector:
    def __init__(self):
        self.lock = threading.Lock()
        self.queries = 0
        self.errors  = 0
        self.updates = 0

    def inc_queries(self):
        with self.lock:
            self.queries += 1

    def inc_errors(self):
        with self.lock:
            self.errors += 1

    def inc_updates(self):
        with self.lock:
            self.updates += 1

    def snapshot(self):
        with self.lock:
            return {
                'queries': self.queries,
                'errors':  self.errors,
                'updates': self.updates,
            }
