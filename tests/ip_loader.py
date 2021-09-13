#!/usr/bin/python
from __future__ import division
from bcc import BPF
import time
from ast import literal_eval
import sys
from countminsketch import CountMinSketch

def help():
    print("execute: {0} <net_interface>".format(sys.argv[0]))
    print("e.g.: {0} eno1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    help()
elif len(sys.argv) == 2:
    INTERFACE = sys.argv[1]

from ctypes import *
import ctypes as ct
import sys
import socket
import os
import struct

OUTPUT_INTERVAL = 1
sample_size = 10
count = 0.0
heavy_hitters = {}
threshold = 0

sketch = CountMinSketch(1000, 10)
bpf = BPF(src_file="ip_reader.c")

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

    # retreive packet_sample map
packet_sample = bpf['packet_sample']

def decimal_to_human(input_value):
    input_value = int(input_value)
    hex_value = hex(input_value)[2:]
    pt3 = literal_eval((str('0x'+str(hex_value[-2:]))))
    pt2 = literal_eval((str('0x'+str(hex_value[-4:-2]))))
    pt1 = literal_eval((str('0x'+str(hex_value[-6:-4]))))
    pt0 = literal_eval((str('0x'+str(hex_value[-8:-6]))))
    result = str(pt0)+'.'+str(pt1)+'.'+str(pt2)+'.'+str(pt3)
    return result


try:
    while True :
        time.sleep(OUTPUT_INTERVAL)
        packet_sample_output = packet_sample.items()
        output_len = len(packet_sample_output)
        
        if output_len < sample_size:
            print("waiting for sample size")
            continue
        
        for i in range(0,output_len):
            pkt_count = 0
            if (len(str(packet_sample_output[i][0]))) != 30:
                continue
            temp = int(str(packet_sample_output[i][0])[8:-2]) # initial output omitted from the kernel space program
            temp = int(str(bin(temp))[2:]) # raw file
            src = int(str(temp)[:32],2) # part1 
            pkt_count = sketch.add(src)
            hit_percent = (pkt_count/output_len) * 100
            if (hit_percent>threshold):
                heavy_hitters[decimal_to_human(str(src))]=pkt_count
            monitor_result = 'source address : ' + decimal_to_human(str(src)) + ' ' + 'destination address : ' + \
            decimal_to_human(str(dst)) + ' ' + pkt_num + ' ' + 'time : ' + str(time.localtime()[0])+\
            ';'+str(time.localtime()[1]).zfill(2)+';'+str(time.localtime()[2]).zfill(2)+';'+\
            str(time.localtime()[3]).zfill(2)+';'+str(time.localtime()[4]).zfill(2)+';'+\
            str(time.localtime()[5]).zfill(2)
            #print(monitor_result)

        print(heavy_hitters)
        packet_sample.clear()

            # time.time() outputs time elapsed since 00:00 hours, 1st, Jan., 1970.
        # delete map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass