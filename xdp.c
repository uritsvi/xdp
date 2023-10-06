//go:build ignore

#include "bpf_endian.h"
#include "common.h"
#include "bpf_helpers.h"

#include <stddef.h>
#include <linux/tcp.h>


char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define PAYLOAD_SIZE (1 << 12)


/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address
	__type(value, __u32); // packet count

	
} xdp_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct packet{	
	char payload[PAYLOAD_SIZE];

	int payload_size;

	u16 src_port;
	u16 dest_port;

	u32 src;
	u32 dest;

};
struct packet *unused_event __attribute__((unused));

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	
	void* data = (void*)ctx->data;
	void* data_end = (void*)ctx->data_end;

	struct ethhdr *ethhdr = (void*)data;
	struct iphdr* iphdr = (void*)(ethhdr + 1);
	struct tcphdr* tcphdr = (void*)(iphdr + 1);

	if ((void *)(ethhdr + 1) > data_end) {
		return XDP_PASS;
	}
	if ((void *)(iphdr + 1) > data_end) {
		return XDP_PASS;
	}
	if ((void *)(tcphdr + 1) >= data_end) {
		return XDP_PASS;
	}

	// Check if ethernet protocol is IPV4 
	if (ethhdr->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	// Pass the packet if the packet's protocol is not TCP
	if(iphdr->protocol != 6){
		return XDP_PASS;
	}

	int header_size = (sizeof(struct ethhdr) + sizeof(struct iphdr) + ((int)tcphdr->doff  * 4));
	int payload_size = (data_end - (data + header_size));

	if(payload_size == 0){
		return XDP_PASS;
	}

	struct packet* event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct packet), 0);
	if(!event){
		return XDP_PASS;
	}
	

	bpf_probe_read_kernel(
		event->payload, 
		PAYLOAD_SIZE, 
		(data + header_size)
	);

	event->payload_size = payload_size;
	event->src_port = (unsigned short int) tcphdr->source;
	event->dest_port = (unsigned short int) tcphdr->dest;

	event->src = iphdr->saddr;
	event->dest = iphdr->daddr;

	bpf_ringbuf_submit(event, 0);

	return XDP_PASS;
}
