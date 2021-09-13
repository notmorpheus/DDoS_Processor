#define KBUILD_MODNAME "monitor"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

//initialize maps
BPF_PERF_OUTPUT(packet_event);
BPF_HASH(ip_map,u32,u32);
BPF_HASH(drop_count,u64,long,256);

//main method
int mitigator(struct xdp_md *ctx) {
  u64 key=0;
  long* count = 0;
  long one = 1;
  u32 *ip;


  void *data_end = (void *)(long)ctx->data_end;
  void *data     = (void *)(long)ctx->data;
  struct ethhdr *eth = data;

  // check packet size
  if (eth + 1 > data_end) {
    return XDP_PASS;
  }

  // get the source address of the packet
  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (iph + 1 > data_end) {
    return XDP_PASS;
  }
  
  u32 ip_src = iph->saddr;

  ip = ip_map.lookup(&ip_src);
  
  count = drop_count.lookup(&key);

  if (ip_src) {
    packet_event.perf_submit(ctx, &ip_src, sizeof(ip_src));

  }
  
  // If source IP not found in the map, forward the traffic.
  if (!ip){
    return XDP_PASS;
  }
  
  //If source IP found in the map, drop the traffic.
  if (ip){
    
    if (count) {
      *count+=1;
    }
    
    else {
      drop_count.update(&key, &one);
    }
    
    return XDP_DROP;
  }

  // drop the packet if the ip source address is equal to ip
  
  
  
  return XDP_PASS;
}