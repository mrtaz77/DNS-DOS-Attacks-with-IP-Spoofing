from enum import Enum

class Attack(Enum):
  TCP_SYN_FLOOD = 1
  ICMP_PING_FLOOD = 2
  ICMP_SMURF_ATTACK = 3
  UDP_FRAGGLE_ATTACK = 4
  UDP_FRAGMENT_FLOOD = 5
