#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import *

def encode_dns(name):
  if len(name) + 1 > 255:
    raise Exception("DNS Name too long.")
  b = bytearray()
  for element in name.split('.'):
    sublen = len(element)
    if sublen > 63:
      raise ValueError('DNS label %s is too long' % element)
    b.append(sublen)
    b.extend(element.encode('ascii'))
  b.append(0)  # Add 0-len octet label for the root server
  return b


def add_entry(table, value):
  key = table.Key()
  key_len = len(key.p)
  name_buffer = encode_dns(value)
  # Pad the buffer with null bytes if it is too short
  name_buffer.extend((0,) * (key_len - len(name_buffer)))
  key.p = (c_ubyte * key_len).from_buffer(name_buffer)
  leaf = table.Leaf()
  leaf.p = (c_ubyte * 4).from_buffer(bytearray(4))
  table[key] = leaf

text ="""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

struct Key {
  unsigned char p[255];
};

struct Leaf {
  // Not really needed in this example
  unsigned char p[4];
};

struct dns_char_t
{
    char c;
} BPF_PACKET_HEADER;

BPF_HASH(test, struct Key, struct Leaf, 128);

int kprobe__sys_clone(void *ctx) {
    struct Key key = {};
    u16 i = 0;
    u8 *cursor = 0;
    struct dns_char_t *c;
    
    struct Leaf * lookup_leaf = test.lookup(&key);
    
    if(lookup_leaf) {
          bpf_trace_printk("%s\\n", &lookup_leaf);
          return -1;
        }

}
"""

dns_list=["foo.bar","abcd.com"]

bpf = BPF(text = text, debug=0)

test = bpf.get_table("test")

for e in dns_list:
    print(">>>> Adding map entry: ", e)
    add_entry(test, e)
    print("entry added")
    bpf.trace_print()