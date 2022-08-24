#ifndef __LIB_FILTER_H_
#define __LIB_FILTER_H_

#include <linux/udp.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef GO_ON
#define GO_ON 99
#endif

typedef struct {
  __u32 ipv4_self;
} config;

/* Use an array map with 1 key as config*/
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, config);
  __uint(max_entries, 3);
} config_port __section(".maps");

#define ETH_P_IP_SWAPPED 0x0008

static __always_inline struct iphdr *parse_ipv4(struct __ctx_buff *ctx) {
    void *data_end = ctx_data_end(ctx);
    void *data = ctx_data(ctx);

    struct iphdr *ipv4_hdr = (struct iphdr *)(data + sizeof(struct ethhdr));
    struct ethhdr *eth = data;

    if (ctx_no_room(ipv4_hdr + 1, data_end) ||
      eth->h_proto != ETH_P_IP_SWAPPED)
        return NULL;

    if (ipv4_hdr->version != 4)
        return NULL;

   return ipv4_hdr;
}

#ifndef UDP_DST_PORT_BE
#define UDP_DST_PORT_BE  0x6808
#endif

static __always_inline int check_udp_gtp_port(struct udphdr *udp_hdr,struct xdp_md* ctx){

    void *data_end = ctx_data_end(ctx);

    if (ctx_no_room(udp_hdr + 1, data_end) != 0)
        return 1;

    if(udp_hdr->dest != UDP_DST_PORT_BE)
        return 1;

    return 0;
}



static __always_inline int n3_packet_filter(struct xdp_md *ctx) {

        struct iphdr *ipv4_hdr = parse_ipv4(ctx);

        //不是ipv4的包，或者不是udp的包，过滤掉
        if (!ipv4_hdr || ipv4_hdr->protocol != IPPROTO_UDP)
            return XDP_PASS;

        //目的地址需要是自己的ip
        __u32 index = 0;
        config *my_config = map_lookup_elem(&config_port, &index);
        if (!my_config || ipv4_hdr->daddr != my_config->ipv4_self)
            return XDP_PASS;

        struct udphdr *udp_hdr = (struct udphdr *)(ipv4_hdr + 1);

        //udp 端口不是2152的包过滤掉
        if (check_udp_gtp_port(udp_hdr,ctx))
            return XDP_PASS;

        return GO_ON;
}

static __always_inline config *get_port_config(__u32* index) {
    return map_lookup_elem(&config_port, index);
}

#endif /* __LIB_FILTER_H_ */