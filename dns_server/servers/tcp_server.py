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
        try:
            # Read 2-byte length prefix first
            length_data = conn.recv(2)
            if len(length_data) < 2:
                return
            
            # Convert length from network byte order
            length = int.from_bytes(length_data, byteorder='big')
            
            # Read the actual DNS message
            data = b''
            while len(data) < length:
                chunk = conn.recv(length - len(data))
                if not chunk:
                    break
                data += chunk
            
            if len(data) == length:
                resp_wire, _ = self.handler.handle(data, addr)
                if resp_wire:
                    # Send response with length prefix
                    resp_length = len(resp_wire).to_bytes(2, byteorder='big')
                    conn.sendall(resp_length + resp_wire)
        except Exception as e:
            print(f"TCP processing error: {e}")
        finally:
            conn.close()
