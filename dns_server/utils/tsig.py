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

    def verify(self, response: dns.message.Message) -> bool:
        # dns.message.from_wire will validate TSIG if keyring passed to resolver
        return response.tsig_okay
