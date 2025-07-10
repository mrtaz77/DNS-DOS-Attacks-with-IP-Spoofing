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

    def clear(self):
        """Clear all cached entries"""
        self._store.clear()

    def remove(self, qname, qtype=None):
        """Remove specific cache entry or all entries for a name"""
        if qtype is not None:
            key = (str(qname), qtype)
            self._store.pop(key, None)
        else:
            # Remove all entries for this name
            to_remove = [k for k in self._store.keys() if k[0] == str(qname)]
            for k in to_remove:
                self._store.pop(k, None)
