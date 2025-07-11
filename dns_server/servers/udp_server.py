# dns_server/servers/udp_server.py
import socket, threading

class UDPServer:
    def __init__(self, handler, addr='0.0.0.0', port=53):
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # allow immediate reuse of address after server restart
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((addr, port))
        print(f"Listening UDP on {addr}:{port}")

    def serve(self):
        try:
            while True:
                data, addr = self.sock.recvfrom(4096)
                threading.Thread(target=self._process, args=(data, addr)).start()
        finally:
            self.sock.close()

    def _process(self, data, addr):
        resp_wire, _ = self.handler.handle(data, addr)
        if resp_wire:
            self.sock.sendto(resp_wire, addr)
