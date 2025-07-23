import dns.tsigkeyring


class TSIGClient:
    """TSIG authentication handler for DNS client"""

    def __init__(self, key_name=None, key_secret=None, file_logger=None):
        self.tsig_enabled = key_name and key_secret
        self.file_logger = file_logger

        if self.tsig_enabled:
            self.keyring = dns.tsigkeyring.from_text({key_name: key_secret})
            self.key_name = key_name
            if self.file_logger:
                self.file_logger.info(f"TSIG - Client initialized with key: {key_name}")
        else:
            self.keyring = None
            self.key_name = None
            if self.file_logger:
                self.file_logger.info("TSIG - Client running without authentication")

    def sign_query(self, query_msg):
        """Sign a DNS query message with TSIG"""
        if self.tsig_enabled:
            query_msg.use_tsig(
                self.keyring, keyname=self.key_name, algorithm="hmac-sha256"
            )
        return query_msg

    def verify_response(self, response_msg):
        """Verify TSIG signature in response (dnspython handles this automatically)"""
        if self.tsig_enabled and hasattr(response_msg, "tsig"):
            return True
        return not self.tsig_enabled  # If no TSIG required, always pass
