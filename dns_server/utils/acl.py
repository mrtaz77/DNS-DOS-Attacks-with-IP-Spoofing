# dns_server/acl.py
import ipaddress

class ACL:
    def __init__(self, allow=None, deny=None):
        self.allow_nets = [ipaddress.ip_network(n) for n in (allow or [])]
        self.deny_nets  = [ipaddress.ip_network(n) for n in (deny  or [])]

    def check(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in self.deny_nets):
            return False
        if self.allow_nets and not any(addr in net for net in self.allow_nets):
            return False
        return True
