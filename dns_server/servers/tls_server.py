# dns_server/servers/tls_server.py
import ssl
from .tcp_server import TCPServer

class TLSServer(TCPServer):
    def __init__(self, handler, addr='0.0.0.0', port=853, certfile=None, keyfile=None):
        super().__init__(handler, addr, port)
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.load_cert_chain(certfile, keyfile)

    def _process(self, conn, addr):
        tls_conn = self.ctx.wrap_socket(conn, server_side=True)
        super()._process(tls_conn, addr)
