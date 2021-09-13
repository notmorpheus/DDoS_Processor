#!/usr/bin/python
from bcc import BPF
import time
import ctypes as ct

device = "ens33"
b = BPF(src_file="filter.c")
fn = b.load_func("mitigator", BPF.XDP)
b.attach_xdp(device, fn, 0)
ip_map = b.get_table("ip_map")

try:
    test_ip = 122622124
    leaf = test_ip
    key=0
    ip_map[ct.c_uint(key)] = ct.c_uint(leaf)
    print("entry successful!")
    b.trace_print()
except KeyboardInterrupt:
    print("Removing filter")
    b.remove_xdp(device,0)

'''
ip is 2886749959
xdp is reading 122622124
'''