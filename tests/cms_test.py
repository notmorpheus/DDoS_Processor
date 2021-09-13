#!/usr/bin/python
from __future__ import division
from countminsketch import CountMinSketch

sketch = CountMinSketch(1000, 10)
sketch.add("a")
#print sketch["a"]
#sketch.add("122.150.82.37")
file1 = open('ipdump.txt', 'r')
ip_addresses = file1.readlines()
count = 0.0
heavy_hitters = {}
hit_percent = (count/len(ip_addresses)) * 100
threshold = 4

for ip in ip_addresses:
    count = 0
    ip.replace(' ','')
    count = sketch.add(ip)
    hit_percent = (count/len(ip_addresses)) * 100
    if hit_percent>threshold:
        heavy_hitters[ip]=count

print (heavy_hitters)
#print sketch.query('122.150.82.37')