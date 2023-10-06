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

#define PACKET_SIZE (1 << 14)

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
	char data[PACKET_SIZE];
	int size;
};
struct packet *unused_event __attribute__((unused));

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {

	struct packet* event;
	event = bpf_ringbuf_reserve(&events, sizeof(struct packet), 0);
	if(!event){
		return XDP_ABORTED;
	}

	bpf_probe_read_kernel(
		event->data, 
		PACKET_SIZE, 
		(void *)(long)ctx->data);

	event->size = (size_t)((void*)ctx->data_end - (void*)ctx->data);

	bpf_ringbuf_submit(event, 0);

	return XDP_PASS;
}
