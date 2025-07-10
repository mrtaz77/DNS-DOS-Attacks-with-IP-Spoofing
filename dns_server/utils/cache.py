# dns_server/cache.py
import time

class Cache:
    def __init__(self):
        self._store = {}  # (str(qname), qtype) -> (expiry, rrset)

    def get(self, qname, qtype):
        key = (str(qname), qtype)
        v = self._store.get(key)
        if v and v[0] > time.time():
            return v[1]
        self._store.pop(key, None)
        return None

    def set(self, qname, qtype, rrset, ttl):
        expiry = time.time() + ttl
        self._store[(str(qname), qtype)] = (expiry, rrset)
