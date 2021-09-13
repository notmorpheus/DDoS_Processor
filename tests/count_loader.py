#!/usr/bin/python
from bcc import BPF
import time
import sys

device = "eth0"
b = BPF(src_file="xdp_count.c")
fn = b.load_func("myprogram", BPF.XDP)
b.attach_xdp(device, fn, 0)
packetcnt = b.get_table("packetcnt")

prev = [0] * 256
print("printing packet counts")
while 1:
    try:
        for k in packetcnt.keys():
            val = packetcnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                print("{}: {} pkt/s".format(i, delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter")
        break
b.remove_xdp(device,0)