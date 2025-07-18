"""
DNS Cache Implementation
Support for multiple cache backends: Simple, LRU, Redis, and Hybrid
"""

import time
import logging
from collections import OrderedDict
from typing import Optional, Union
import threading

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None


class DNSCache:
    """Simple DNS cache implementation (original)"""
    
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


class LRUDNSCache(DNSCache):
    """Enhanced DNS cache with LRU eviction and size limits"""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._store = OrderedDict()  # (qname, qtype) -> (expiry, rrset)
        self._lock = threading.RLock()
        self.stats = {'hits': 0, 'misses': 0, 'sets': 0, 'evictions': 0}
        
    def _make_key(self, qname: str, qtype: str) -> tuple:
        return (str(qname).lower(), qtype.upper())
    
    def get(self, qname, qtype):
        key = self._make_key(qname, qtype)
        
        with self._lock:
            if key in self._store:
                expiry, rrset = self._store[key]
                
                # Check if expired
                if expiry > time.time():
                    # Move to end (most recently used)
                    self._store.move_to_end(key)
                    self.stats['hits'] += 1
                    return rrset
                else:
                    # Expired - remove it
                    del self._store[key]
                    
            self.stats['misses'] += 1
            return None
    
    def set(self, qname, qtype, rrset, ttl):
        key = self._make_key(qname, qtype)
        expiry = time.time() + (ttl or self.default_ttl)
        
        with self._lock:
            # Remove oldest entries if at capacity
            while len(self._store) >= self.max_size:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
                self.stats['evictions'] += 1
            
            # Add/update entry
            self._store[key] = (expiry, rrset)
            self._store.move_to_end(key)  # Mark as most recently used
            self.stats['sets'] += 1
    
    def clear(self):
        with self._lock:
            self._store.clear()
    
    def remove(self, qname, qtype=None):
        with self._lock:
            if qtype is not None:
                key = self._make_key(qname, qtype)
                self._store.pop(key, None)
            else:
                # Remove all entries for this name
                qname_lower = str(qname).lower()
                keys_to_remove = [k for k in self._store.keys() if k[0] == qname_lower]
                for k in keys_to_remove:
                    del self._store[k]
    
    def get_size(self) -> int:
        """Get current cache size"""
        with self._lock:
            return len(self._store)
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
        return {
            **self.stats,
            'hit_rate': f"{hit_rate:.1f}%",
            'total_requests': total,
            'size': self.get_size(),
            'max_size': self.max_size
        }


class RedisDNSCache(DNSCache):
    """Redis-based DNS cache for persistence and clustering"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0", 
                 key_prefix: str = "dns_cache:", default_ttl: int = 300):
        if not REDIS_AVAILABLE:
            raise ImportError("Redis library not available. Install with: pip install redis")
        
        self.redis_client = redis.from_url(redis_url)
        self.key_prefix = key_prefix
        self.default_ttl = default_ttl
        self.stats = {'hits': 0, 'misses': 0, 'sets': 0, 'evictions': 0}
        
        # Test connection
        try:
            self.redis_client.ping()
            logging.info("Connected to Redis cache at %s", redis_url)
        except Exception as e:
            logging.error("Failed to connect to Redis: %s", e)
            raise
    
    def _make_key(self, qname: str, qtype: str) -> str:
        return f"{self.key_prefix}{str(qname).lower()}:{qtype.upper()}"
    
    def get(self, qname, qtype):
        try:
            import pickle
            key = self._make_key(qname, qtype)
            data = self.redis_client.get(key)
            
            if data:
                rrset = pickle.loads(data)
                self.stats['hits'] += 1
                return rrset
            else:
                self.stats['misses'] += 1
                return None
                
        except Exception as e:
            logging.warning("Redis cache get error: %s", e)
            self.stats['misses'] += 1
            return None
    
    def set(self, qname, qtype, rrset, ttl):
        try:
            import pickle
            key = self._make_key(qname, qtype)
            data = pickle.dumps(rrset)
            effective_ttl = ttl or self.default_ttl
            
            self.redis_client.setex(key, effective_ttl, data)
            self.stats['sets'] += 1
            
        except Exception as e:
            logging.warning("Redis cache set error: %s", e)
    
    def clear(self):
        try:
            pattern = f"{self.key_prefix}*"
            keys = self.redis_client.keys(pattern)
            if keys:
                self.redis_client.delete(*keys)
        except Exception as e:
            logging.warning("Redis cache clear error: %s", e)
    
    def remove(self, qname, qtype=None):
        try:
            if qtype is not None:
                key = self._make_key(qname, qtype)
                self.redis_client.delete(key)
            else:
                pattern = f"{self.key_prefix}{str(qname).lower()}:*"
                keys = self.redis_client.keys(pattern)
                if keys:
                    self.redis_client.delete(*keys)
        except Exception as e:
            logging.warning("Redis cache remove error: %s", e)
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        total = self.stats['hits'] + self.stats['misses']
        hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
        return {
            **self.stats,
            'hit_rate': f"{hit_rate:.1f}%",
            'total_requests': total,
            'type': 'redis'
        }


class HybridDNSCache(DNSCache):
    """Hybrid cache using both in-memory LRU and Redis"""
    
    def __init__(self, memory_cache_size: int = 1000, redis_url: str = "redis://localhost:6379/0",
                 key_prefix: str = "dns_cache:", default_ttl: int = 300):
        
        # L1 cache: Fast in-memory LRU
        self.l1_cache = LRUDNSCache(max_size=memory_cache_size, default_ttl=default_ttl)
        
        # L2 cache: Persistent Redis (optional)
        self.l2_cache = None
        if REDIS_AVAILABLE:
            try:
                self.l2_cache = RedisDNSCache(redis_url, key_prefix, default_ttl)
                logging.info("Hybrid cache: L1 (memory) + L2 (Redis) enabled")
            except Exception as e:
                logging.warning("Redis L2 cache disabled: %s", e)
                logging.info("Using L1 (memory) cache only")
        else:
            logging.info("Redis not available, using L1 (memory) cache only")
        
        self.stats = {'hits': 0, 'misses': 0, 'sets': 0, 'evictions': 0}
    
    def get(self, qname, qtype):
        # Try L1 cache first (fastest)
        result = self.l1_cache.get(qname, qtype)
        if result is not None:
            self.stats['hits'] += 1
            return result
        
        # Try L2 cache if available
        if self.l2_cache:
            result = self.l2_cache.get(qname, qtype)
            if result is not None:
                # Promote to L1 cache
                self.l1_cache.set(qname, qtype, result, 300)
                self.stats['hits'] += 1
                return result
        
        self.stats['misses'] += 1
        return None
    
    def set(self, qname, qtype, rrset, ttl):
        # Store in both caches
        self.l1_cache.set(qname, qtype, rrset, ttl)
        if self.l2_cache:
            self.l2_cache.set(qname, qtype, rrset, ttl)
        self.stats['sets'] += 1
    
    def clear(self):
        self.l1_cache.clear()
        if self.l2_cache:
            self.l2_cache.clear()
    
    def remove(self, qname, qtype=None):
        self.l1_cache.remove(qname, qtype)
        if self.l2_cache:
            self.l2_cache.remove(qname, qtype)
    
    def get_stats(self) -> dict:
        stats = {**self.stats}
        total = stats['hits'] + stats['misses']
        hit_rate = (stats['hits'] / total * 100) if total > 0 else 0
        stats['hit_rate'] = f"{hit_rate:.1f}%"
        stats['total_requests'] = total
        stats['l1_cache_size'] = self.l1_cache.get_size()
        stats['l2_cache_enabled'] = self.l2_cache is not None
        stats['type'] = 'hybrid'
        return stats


def create_cache(cache_type: str = "lru", **kwargs) -> DNSCache:
    """
    Factory function to create DNS cache instances
    
    Args:
        cache_type: "simple", "lru", "redis", or "hybrid"
        **kwargs: Cache-specific configuration
    
    Returns:
        DNS cache instance
    """
    if cache_type == "simple":
        return DNSCache()
    elif cache_type == "lru":
        return LRUDNSCache(**kwargs)
    elif cache_type == "redis":
        return RedisDNSCache(**kwargs)
    elif cache_type == "hybrid":
        return HybridDNSCache(**kwargs)
    else:
        raise ValueError(f"Unknown cache type: {cache_type}")


# Backward compatibility
Cache = DNSCache
