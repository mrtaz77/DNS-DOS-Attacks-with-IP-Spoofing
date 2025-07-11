# dns_server/servers/doh_server.py
import re
from .tls_server import TLSServer
import dns.message

class DoHServer(TLSServer):
    def _process(self, conn, addr):
        http = conn.recv(1024).decode()
        length = int(re.search(r'Content-Length: (\d+)', http).group(1))
        body = conn.recv(length)
        resp_wire, _ = self.handler.handle(body, addr)
        hdr = (
            'HTTP/1.1 200 OK\r\n'
            'Content-Type: application/dns-message\r\n'
            f'Content-Length: {len(resp_wire)}\r\n\r\n'
        )
        conn.send(hdr.encode() + resp_wire)
        conn.close()
