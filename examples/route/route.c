// +build ignore

#include <bpf/ctx/xdp.h>

#include "node_config.h"

#include <bpf/api.h>
#include <bpf/helpers.h>
#include <linux/ip.h>

#include "lib/eth.h"
#include "route.h"

char __license[] __section("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16
#define NULL ((void *)0)

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map __section(".maps");

typedef struct {
	__u32 ipv4_self;
} config;

/* Use an array map with 1 key as config*/
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, config);
	__uint(max_entries, 1);
} config_route __section(".maps");

static __always_inline struct iphdr *parseIpv4(struct __ctx_buff *ctx) {
	void *data_end = ctx_data_end(ctx);
	void *data     = ctx_data(ctx);

	struct iphdr *ipv4_hdr = data + sizeof(struct ethhdr);
	struct ethhdr *eth     = data;

	if (ctx_no_room(ipv4_hdr + 1, data_end) || eth->h_proto != bpf_htons(ETH_P_IP))
		return NULL;

	if (ipv4_hdr->version != 4)
		return NULL;

	return ipv4_hdr;
}

static __always_inline int redirect_direct_v4(struct __ctx_buff *ctx, struct iphdr *ip4) {
	int ret;

	struct bpf_fib_lookup fib_params = {
		.family   = AF_INET,
		.ifindex  = ctx->ingress_ifindex,
		.ipv4_src = ip4->saddr,
		.ipv4_dst = ip4->daddr,
	};

	ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	switch (ret) {
	case BPF_FIB_LKUP_RET_SUCCESS:
		break;
	case BPF_FIB_LKUP_RET_NO_NEIGH:
		return CTX_ACT_OK;
	default:
		return CTX_ACT_DROP;
	}

	if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
		return CTX_ACT_DROP;
	if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
		return CTX_ACT_DROP;
	return ctx_redirect(ctx, fib_params.ifindex, 0);
}

__section("xdp") int xdp_prog_func(struct xdp_md *ctx) {
	struct iphdr *ipv4_hdr = parseIpv4(ctx);

	if (!ipv4_hdr)
		return CTX_ACT_OK;

	__u32 index       = 0;
	config *my_config = map_lookup_elem(&config_route, &index);

	// 如果目的IP地址是自己，则不进行转发
	if (!my_config || ipv4_hdr->daddr == my_config->ipv4_self) {
		return CTX_ACT_OK;
	}

	__u32 *pkt_count = map_lookup_elem(&xdp_stats_map, &(ipv4_hdr->saddr));
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		map_update_elem(&xdp_stats_map, &(ipv4_hdr->saddr), &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

	return redirect_direct_v4(ctx, ipv4_hdr);
}
