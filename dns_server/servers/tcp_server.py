# dns_server/servers/tcp_server.py
import socket, threading

class TCPServer:
    def __init__(self, handler, addr='0.0.0.0', port=53):
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # allow immediate reuse of address after server restart
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((addr, port))
        self.sock.listen(5)
        print(f"Listening TCP on {addr}:{port}")

    def serve(self):
        try:
            while True:
                conn, addr = self.sock.accept()
                threading.Thread(target=self._process, args=(conn, addr)).start()
        finally:
            self.sock.close()

    def _process(self, conn, addr):
        data = conn.recv(4096)
        resp, _ = self.handler.handle(data, addr)
        if resp:
            conn.sendall(resp)
        conn.close()
