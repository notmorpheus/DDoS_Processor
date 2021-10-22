#!/usr/bin/python3
from __future__ import division
from bcc import BPF
import time
from ast import literal_eval
import sys
from countminsketch import CountMinSketch

from ctypes import *
import ctypes as ct
import sys
import socket
import os
import struct

#Configuration
device = sys.argv[1] #interface the program needs to deploy the XDP on
OUTPUT_INTERVAL = 10 #read dropped packets after block
sample_size = 1000 #no. of packets to collect to determine heavy hitters
threshold_percent = 60 #criteria as to who are heavy hitters
#end configuration

count = 0 
sketch = CountMinSketch(1000, 10)
event_list =[]


#process each incoming source uninsigned int from BPF ring buffer
def process_event(cpu, data, size):

    global count
    src = ct.cast(data, ct.POINTER(ct.c_uint64)).contents.value   
    event_list.append(int(src))
    count+=1

#read the drop count from the map and return a decimal from long tuple 
def read_count(c_map):

    c_list = c_map.items()
    if (len(c_list)!=1):
        return 0
    else:
        return int(str(c_list[0][1])[7:-1])


#feed source ips into CMS to obtain lossy count and check for threshold
def detect_ddos(event_list,threshold_percent):

    pkt_count = 0
    heavy_hitters ={}

    for ip in event_list:
        pkt_count = sketch.add(ip)
        hit_percent = (pkt_count/len(event_list)) * 100
        if (hit_percent>threshold_percent):
            heavy_hitters[ip]=pkt_count
    return heavy_hitters

#send the detected source IPs back to kernel space for blocking traffic
def mitigate_ddos(b_map,hitters):
    
    idx=0
    if(len(hitters)!=0):
        for ip in hitters.keys():
            key = ip
            leaf=idx
            b_map[ct.c_uint(key)] = ct.c_uint(leaf)
            idx+=1
        print("IPs sent to XDP for mitigation!")
    else:
        print("No hitters identified")

#convert u32 IP address to human IP notation 
def decimal_to_human(input_value):
    input_value = int(input_value)
    hex_value = hex(input_value)[2:]
    pt3 = literal_eval((str('0x'+str(hex_value[-2:]))))
    pt2 = literal_eval((str('0x'+str(hex_value[-4:-2]))))
    pt1 = literal_eval((str('0x'+str(hex_value[-6:-4]))))
    pt0 = literal_eval((str('0x'+str(hex_value[-8:-6]))))
    result = str(pt0)+'.'+str(pt1)+'.'+str(pt2)+'.'+str(pt3)
    return result

#print IP addresses in human readable Notation   
def identify_hitters(hitters):
    if(len(hitters)!=0):
        for hitter in hitters.keys():
            temp=decimal_to_human(hitter)
            print("Source IP: {} with total packets identified before confirm DoS: {}".format(temp,hitters[hitter]))

#initialize the BPF program
b = BPF(src_file="filter.c")

fn = b.load_func("mitigator", BPF.XDP)
b.attach_xdp(device, fn, 0)

ip_map = b.get_table("ip_map")

drop_count = b.get_table("drop_count")

b["packet_event"].open_perf_buffer(process_event)


delta_list=[]

print("=========================DDOS PROCESSOR=============================\n")

try:
    while True :
        b.perf_buffer_poll()
        print("Collecting a sample of packets, count currently at {} packets.".format(count))
        cnt = read_count(drop_count)
        if (cnt>0):
            print("DDoS Mitigation in effect! {} packets dropped so far".format(cnt))
            delta_list.extend([cnt,time.time()])
            if(len(delta_list)==4):
                secs_passed = delta_list[3]-delta_list[1]
                packets_dropped = delta_list[2] - delta_list[0]
                pps = packets_dropped/secs_passed
                print ("Drop Rate: {} pkts/sec".format(pps))
                delta_list=[]
                
        if (count >=sample_size):
            hitters = detect_ddos(event_list,threshold_percent)
            identify_hitters(hitters)
            
            print("performing DDOS mitigation...")
            mitigate_ddos(ip_map,hitters)
            
            #cleanup
            event_list=[]
            sketch = CountMinSketch(1000, 10)
            count = 0
            time.sleep(OUTPUT_INTERVAL)

except KeyboardInterrupt:
    print("Removing filter")
    drop_count.clear()
    ip_map.clear()
    b.remove_xdp(device,0)
    

