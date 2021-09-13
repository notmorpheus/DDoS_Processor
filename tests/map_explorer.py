#This is what the hashmap table looks like->
# [(c_ulong(12398496642751287045L), c_long(1)), (c_ulong(6610540560804499205L), c_long(1)), (c_ulong(12398496658583542685L), c_long(1)), (c_ulong(12398496659931156225L), c_long(1))]

a = ('c_ulong(12398496642751287045L)', 'c_long(1)')

#this will give us the IP address in decimal which we can then convert to bit notation 
print(str(a[0])[8:-2])

'''
00 -> 12398496642751287045 is 172.16.79.5
10 -> 6610540560804499205 is 172.16.79.5
20 -> 12398496658583542685 is 91.189.91.157
30 -> 12398496659931156225 is 172.16.79.1
