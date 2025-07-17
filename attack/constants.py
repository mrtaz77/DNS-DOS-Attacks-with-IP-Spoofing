from enum import Enum

class Attack(Enum):
    UDP_FRAGMENT_FLOOD = 1
    DNS_RANDOM_SUBDOMAIN_QUERY_FLOOD = 2
