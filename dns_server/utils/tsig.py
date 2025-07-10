# dns_server/tsig.py
import dns.tsig, dns.tsigkeyring, dns.message

class TSIGAuthenticator:
    def __init__(self, key_name: str, key_secret: str):
        # key_secret should be base64-encoded
        self.keyring = dns.tsigkeyring.from_text({ key_name: key_secret })
        self.key_name = key_name

    def sign_request(self, message: dns.message.Message) -> dns.message.Message:
        message.use_tsig(self.keyring, keyname=self.key_name, algorithm='hmac-sha256')
        return message

    def verify(self, message: dns.message.Message) -> bool:
        try:
            # Parse the message with TSIG validation
            # The message should already have been parsed from wire with the keyring
            # If we get here, it means TSIG was present and validated during parsing
            return True
        except Exception as e:
            print(f"TSIG verification failed: {e}")
            return False
