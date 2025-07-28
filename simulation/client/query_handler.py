import socket
import struct
import time
import random
import ssl
from dns_cookies_client import (
    DNSCookieClient,
    add_cookie_to_dns_query_raw,
    extract_cookie_from_response,
)


class DNSQueryHandler:
    """DNS query execution and response handling using raw sockets"""

    def __init__(
        self,
        file_logger,
        bind_ip=None,
        bind_port=None,
        use_cookies=False,
        use_tls=False,
        tls_certfile=None,
        tls_keyfile=None,
    ):
        self.file_logger = file_logger
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.use_cookies = use_cookies
        self.cookie_client = DNSCookieClient() if use_cookies else None
        self.use_tls = use_tls
        self.tls_certfile = tls_certfile
        self.tls_keyfile = tls_keyfile

    def _build_dns_query(self, qname, qtype="A"):
        # Transaction ID: fixed 16-bit
        txid = 0x1337
        # Flags: standard query, recursion desired
        flags = 0x0100
        qdcount = 1
        ancount = nscount = arcount = 0
        header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)

        # QNAME: sequence of labels ending with 0
        def encode_qname(name):
            parts = name.rstrip(".").split(".")
            res = b""
            for part in parts:
                res += bytes([len(part)]) + part.encode()
            res += b"\x00"
            return res

        qname_bytes = encode_qname(qname)
        # QTYPE: 1 for A, 28 for AAAA, etc.
        qtype_map = {"A": 1, "AAAA": 28, "MX": 15, "CNAME": 5, "NS": 2, "TXT": 16}
        qtype_val = qtype_map.get(qtype.upper(), 1)
        qclass = 1  # IN
        question = qname_bytes + struct.pack("!HH", qtype_val, qclass)

        return header + question, txid

    def _parse_dns_response(self, data, txid):
        # Parse header
        if len(data) < 12:
            return {
                "success": False,
                "error": "SHORT_RESPONSE",
                "output": "Short DNS response",
            }
        resp_txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
            "!HHHHHH", data[:12]
        )
        if resp_txid != txid:
            return {
                "success": False,
                "error": "TXID_MISMATCH",
                "output": "Transaction ID mismatch",
            }
        rcode = flags & 0xF
        rcode_map = {
            0: "NOERROR",
            1: "FORMERR",
            2: "SERVFAIL",
            3: "NXDOMAIN",
            4: "NOTIMP",
            5: "REFUSED",
        }
        rcode_str = rcode_map.get(rcode, str(rcode))

        # Skip question section
        offset = 12
        for _ in range(qdcount):
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1  # null byte
            offset += 4  # QTYPE + QCLASS

        answers, _ = self._parse_answers(data, offset, ancount)

        return {
            "success": True,
            "rcode": rcode_str,
            "answers_count": len(answers),
            "output": ", ".join(answers) if answers else "",
        }

    def _parse_answers(self, data, offset, ancount):
        answers = []
        for _ in range(ancount):
            offset = self._skip_name(data, offset)
            atype, _aclass, _ttl, rdlength = struct.unpack(
                "!HHIH", data[offset : offset + 10]
            )
            offset += 10
            rdata = data[offset : offset + rdlength]
            offset += rdlength
            answer = self._parse_answer_by_type(data, atype, rdata)
            answers.append(answer)
        return answers, offset

    def _skip_name(self, data, offset):
        if data[offset] & 0xC0 == 0xC0:
            return offset + 2
        while data[offset] != 0:
            offset += data[offset] + 1
        return offset + 1

    def _parse_answer_by_type(self, data, atype, rdata):
        if atype == 1 and len(rdata) == 4:  # A record (IPv4)
            return self._parse_a_record(rdata)
        elif atype == 28 and len(rdata) == 16:  # AAAA record (IPv6)
            return self._parse_aaaa_record(rdata)
        elif atype == 5:  # CNAME
            return self._parse_cname_record(data, rdata)
        elif atype == 15:  # MX
            return self._parse_mx_record(data, rdata)
        elif atype == 2:  # NS
            return self._parse_ns_record(data, rdata)
        elif atype == 16:  # TXT
            return self._parse_txt_record(rdata)
        elif atype == 46:  # RRSIG
            return self._parse_rrsig_record(data, rdata)
        elif atype == 13:  # HINFO
            return self._parse_hinfo_record(rdata)
        elif atype == 48:  # DNSKEY
            return self._parse_dnskey_record(rdata)
        elif atype == 255:  # ANY
            return "ANY:(raw data omitted)"
        else:
            return f"TYPE{atype}({len(rdata)} bytes)"

    def _parse_a_record(self, rdata):
        return ".".join(str(b) for b in rdata)

    def _parse_aaaa_record(self, rdata):
        return ":".join(f"{rdata[i]<<8 | rdata[i+1]:x}" for i in range(0, 16, 2))

    def _parse_cname_record(self, data, rdata):
        # Parse a DNS name from rdata, using DNS compression if needed
        try:
            # rdata is a slice of the original DNS message, but pointers (compression) refer to the full message
            # So we need to parse the name starting at the offset of rdata in the original message
            # But since we only have rdata, we can reconstruct the offset by finding rdata in data
            # Instead, let's use a helper that can parse a DNS name from any offset in the original message
            cname = self._parse_dns_name_from_message(data, rdata)
            return f"CNAME:{cname}"
        except Exception:
            return "CNAME:(parse error)"

    def _parse_dns_name_from_message(self, data, rdata):
        # Parse a DNS name from a message, handling compression pointers
        labels = []
        offset = 0
        jumps = 0
        max_jumps = 10  # Prevent infinite loops

        while offset < len(rdata):
            length = rdata[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                label, offset = self._handle_compression_pointer(
                    data, rdata, offset, jumps, max_jumps
                )
                if label is not None:
                    labels.append(label)
                break
            else:
                offset += 1
                labels.append(rdata[offset : offset + length].decode(errors="replace"))
                offset += length
        return ".".join(labels)

    def _handle_compression_pointer(self, data, rdata, offset, jumps, max_jumps):
        # Helper for handling DNS compression pointers
        if offset + 1 >= len(rdata):
            return None, offset + 2
        pointer = ((rdata[offset] & 0x3F) << 8) | rdata[offset + 1]
        if pointer >= len(data) or jumps > max_jumps:
            return None, offset + 2
        label, _ = self._parse_dns_name_from_message(data, data[pointer:])
        jumps += 1
        return label, offset + 2

    def _parse_mx_record(self, data, rdata):
        try:
            # MX: preference (2 bytes) + exchange (domain name, possibly compressed)
            if len(rdata) < 3:
                return "MX:(parse error)"
            preference = struct.unpack("!H", rdata[:2])[0]
            # If the exchange is a CNAME (as in your dig output), rdata[2:] will be a compressed name or pointer
            # If rdata[2] is 0xc0 or similar, it's a pointer; otherwise, it's a label
            # Use the same DNS name parser as for NS/CNAME
            exchange, _ = self._parse_dns_name_full(data, rdata, offset=2)
            return f"MX:{preference} {exchange}"
        except Exception:
            return "MX:(parse error)"

    def _parse_ns_record(self, data, rdata):
        try:
            # NS rdata is a domain name, possibly compressed, relative to the original DNS message
            ns, _ = self._parse_dns_name_full(data, rdata)
            return f"NS:{ns}"
        except Exception:
            return "NS:(parse error)"

    def _parse_dns_name_full(self, data, rdata, offset=0):
        """
        Parse a DNS name from a message, handling compression pointers.
        This version works for rdata slices by following pointers into the full DNS message.
        """
        labels = []
        jumps = 0
        max_jumps = 10
        pos = offset
        while True:
            if pos >= len(rdata):
                break
            length = rdata[pos]
            if length == 0:
                pos += 1
                break
            if (length & 0xC0) == 0xC0:
                # Compression pointer: get the pointer offset from the original message
                if pos + 1 >= len(rdata):
                    break
                pointer = ((length & 0x3F) << 8) | rdata[pos + 1]
                if pointer >= len(data) or jumps > max_jumps:
                    break
                label, _ = self._parse_dns_name_full(data, data, pointer)
                labels.append(label)
                pos += 2
                break
            else:
                pos += 1
                labels.append(rdata[pos : pos + length].decode(errors="replace"))
                pos += length
        return ".".join(labels), pos

    def _parse_txt_record(self, rdata):
        try:
            txts = []
            idx = 0
            while idx < len(rdata):
                txt_len = rdata[idx]
                txt = rdata[idx + 1 : idx + 1 + txt_len].decode(errors="replace")
                txts.append(txt)
                idx += 1 + txt_len
            return f"TXT:{' '.join(txts)}"
        except Exception:
            return "TXT:(decode error)"

    def _parse_rrsig_record(self, data, rdata):
        try:
            type_covered, algorithm, labels, orig_ttl, sig_exp, sig_incept, key_tag = (
                struct.unpack("!HBBIIIH", rdata[:18])
            )
            signer_name, _ = self._parse_name(data, rdata[18:])
            return f"RRSIG:{type_covered} alg={algorithm} labels={labels} orig_ttl={orig_ttl} sig_exp={sig_exp} sig_incept={sig_incept} key_tag={key_tag} signer={signer_name}"
        except Exception:
            return "RRSIG:(parse error)"

    def _parse_dnskey_record(self, rdata):
        try:
            flags, protocol, algorithm = struct.unpack("!HBB", rdata[:4])
            key_data = rdata[4:]
            return f"DNSKEY:flags={flags} protocol={protocol} alg={algorithm} keylen={len(key_data)}"
        except Exception:
            return "DNSKEY:(parse error)"

    def _parse_hinfo_record(self, rdata):
        try:
            # HINFO: <CPU> <OS>, both as counted strings
            if len(rdata) < 2:
                return "HINFO:(parse error)"
            cpu_len = rdata[0]
            if 1 + cpu_len > len(rdata):
                return "HINFO:(parse error)"
            cpu = rdata[1 : 1 + cpu_len].decode(errors="replace")
            os_len_offset = 1 + cpu_len
            if os_len_offset >= len(rdata):
                os = ""
            else:
                os_len = rdata[os_len_offset]
                if os_len_offset + 1 + os_len > len(rdata):
                    os = ""
                else:
                    os = rdata[os_len_offset + 1 : os_len_offset + 1 + os_len].decode(
                        errors="replace"
                    )
            return f"HINFO:CPU={cpu} OS={os}"
        except Exception:
            return "HINFO:(parse error)"

    def _recv_exact(self, sock, n):
        """Helper to receive exactly n bytes from a socket."""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed before receiving expected data")
            data += chunk
        return data

    def send_query(self, server_ip, server_port, qname, qtype, timeout=10):
        """Send DNS query using raw sockets (UDP only)"""
        try:
            query, txid = self._build_dns_query(qname, qtype)

            # Add DNS Cookie if enabled
            if self.use_cookies and self.cookie_client:
                client_cookie = self.cookie_client.get_client_cookie()
                server_cookie = self.cookie_client.get_server_cookie(server_ip)
                query = add_cookie_to_dns_query_raw(query, client_cookie, server_cookie)
                self.file_logger.debug(
                    f"DNS_QUERY_COOKIE - Added cookie to {qname} {qtype} query (client={client_cookie.hex()[:8]}..., server={'present' if server_cookie else 'none'})"
                )

            self.file_logger.debug(
                f"DNS_QUERY - {qname} {qtype} to {server_ip}:{server_port}"
            )
            start = time.time()
            if self.use_tls:
                context = ssl.create_default_context()
                # Allow self-signed certs for local testing
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                if self.tls_certfile and self.tls_keyfile:
                    context.load_cert_chain(
                        certfile=self.tls_certfile, keyfile=self.tls_keyfile
                    )
                with socket.create_connection(
                    (server_ip, server_port), timeout=timeout
                ) as sock:
                    with context.wrap_socket(
                        sock, server_hostname=None
                    ) as tls_sock:
                        tls_sock.sendall(len(query).to_bytes(2, "big") + query)
                        resp_len_bytes = self._recv_exact(tls_sock, 2)
                        resp_len = int.from_bytes(resp_len_bytes, "big")
                        response = self._recv_exact(tls_sock, resp_len)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                if self.bind_ip or self.bind_port:
                    sock.bind((self.bind_ip or "", self.bind_port or 0))
                sock.sendto(query, (server_ip, server_port))
                try:
                    data, _ = sock.recvfrom(4096)
                    response = data
                except socket.timeout:
                    return {
                        "success": False,
                        "elapsed": timeout,
                        "error": "TIMEOUT",
                        "output": "DNS query timeout",
                        "parsing_time": 0,
                    }
                finally:
                    sock.close()

            # --- Measure parsing time ---
            parse_start = time.time()
            resp = self._parse_dns_response(response, txid)
            parse_end = time.time()
            parsing_time = parse_end - parse_start

            # Extract and store DNS Cookie from response if present
            if self.use_cookies and self.cookie_client and resp.get("success"):
                _, server_cookie_resp = extract_cookie_from_response(response)
                if server_cookie_resp:
                    self.cookie_client.store_server_cookie(
                        server_ip, server_cookie_resp
                    )
                    self.file_logger.debug(
                        f"DNS_COOKIE_STORED - Server cookie stored for {server_ip}"
                    )
            # ---------------------------
            resp["elapsed"] = time.time() - start
            resp["parsing_time"] = parsing_time
            return resp
        except Exception as e:
            return {
                "success": False,
                "elapsed": 0,
                "error": "EXCEPTION",
                "output": str(e),
                "parsing_time": 0,
            }

    def test_connectivity(self, server, port):
        """Test basic connectivity using raw DNS packets"""
        from logger import console

        console.print(f"[yellow]🔍 Testing connectivity to {server}:{port}...[/yellow]")
        self.file_logger.info(
            f"CONNECTIVITY_TEST - Testing connection to {server}:{port}"
        )
        result = self.send_query(server, port, "google.com.", "A", timeout=5)
        if result["success"]:
            console.print(
                f"[green]✅ Connectivity test successful ({result.get('elapsed', 0):.3f}s)[/green]"
            )
            self.file_logger.info(
                f"CONNECTIVITY_TEST - Success, response time: {result.get('elapsed', 0):.3f}s"
            )
            return True
        else:
            console.print(
                f"[red]❌ Connectivity test failed: {result.get('error', 'UNKNOWN')}[/red]"
            )
            self.file_logger.error(
                f"CONNECTIVITY_TEST - Failed: {result.get('error', 'UNKNOWN')}"
            )
            return False
