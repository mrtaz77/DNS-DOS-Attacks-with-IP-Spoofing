from enum import Enum

class Attack(Enum):
    DNS_REPLY_FLOOD = 1
    DNS_RANDOM_SUBDOMAIN_QUERY_FLOOD = 2
