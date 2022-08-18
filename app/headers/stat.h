#ifndef __LINUX_STAT_H__
#define __LINUX_STAT_H__

#include "node_config.h"
#include <bpf/helpers.h>

typedef struct {
    __u64 total_received_bytes;
    __u64 total_forward_bytes;
    __u64 total_received_packets;
    __u64 total_forward_packets;
} stat_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u16);
    __type(value, stat_t);
    __uint(max_entries, 1024);
} ul_stat __section(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u16);
    __type(value, stat_t);
    __uint(max_entries, 1024);
} dl_stat __section(".maps");


static __always_inline stat_t * get_dl_stat(__u16 id) {
    __u16 key = id;
    return map_lookup_elem(&dl_stat, &key);
}

static __always_inline  stat_t * get_ul_stat(__u16 id) {
    __u16 key = id;
    return map_lookup_elem(&ul_stat, &key);
}


#endif /* __LINUX_STAT_H__ */