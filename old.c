//go:build ignore

#include "bpf_endian.h"
#include "common.h"
#include "bpf_helpers.h"

#include <stddef.h>


char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define PACKET_SIZE (1 << 12)

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

struct event{
	char buffer[PACKET_SIZE];
	int size;
};
struct event *unused_event __attribute__((unused));


/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_src_addr(	
	struct xdp_md *ctx, 
	__u32 *ip_src_addr, 
	char** buffer, 
	__u32* size) {

	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}


	/*only for incoming*/
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	/*
	if((void*)((void*)(ip + 1) + PACKET_SIZE) > data_end){
		return 0;
	}
	*/

	struct tcphdr* a;
	
	*buffer = (char*)(ip + 1);

	*size = (__u32)(data_end - ((void*)(ip + 1)));

	return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	char* buffer_ptr;
	__u32 len;
	__u32 ip;
	
	if (!parse_ip_src_addr(
		ctx, 
		&ip, 
		&buffer_ptr,
		&len)) {
		// Not an IPv4 packet, so don't count it.
		return XDP_ABORTED;
	}

	if(len <= 0){
		return XDP_ABORTED;
	}

	__u32 size = len;
	if(len > PACKET_SIZE){
		size = PACKET_SIZE;
	}

	struct event* event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if(!event){
		return XDP_ABORTED;
	}

	event->size = size;
	
	if(size < 0){
		return XDP_ABORTED;
	}
	bpf_probe_read_kernel((void*)event->buffer, PACKET_SIZE, (const void*)buffer_ptr);


	
	bpf_ringbuf_submit(event, 0);
done:


	// Try changing this to XDP_DROP and see what happens!
	return XDP_PASS;
}
