#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

# run in project examples directory with:
# sudo ./hello_world.py"
# see trace_fields.py for a longer example

from bcc import BPF
import ctypes as ct


# This may not work for 4.17 on x64, you need replace kprobe__sys_clone with kprobe____x64_sys_clone
text ="""
#include <uapi/linux/bpf.h>

BPF_HASH(test, u32, u32, 128);


int kprobe__sys_clone(void *ctx) 
{
    u32 key = 0;
    u32 *ip;
    ip = test.lookup(&key);
    
    if(ip) { 
          bpf_trace_printk("%u\\n", *ip);
          return 0;
        }
     else {
        bpf_trace_printk("Hello, World!\\n"); 
        return 0; 
        }
}

"""

b = BPF(text=text)
ip_map = b.get_table("test")

test_ip = 2886749959
key=0
leaf = test_ip

ip_map[ct.c_uint(key)] = ct.c_uint(leaf)

b.trace_print()
