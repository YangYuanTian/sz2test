#ifndef __LINUX_STAT_H__
#define __LINUX_STAT_H__

#include <bpf/helpers.h>

typedef struct {
    __u64 total_received_bytes;
    __u64 total_forward_bytes;
    __u64 total_received_packets;
    __u64 total_forward_packets;
} stat_t;

#ifndef MAX_MAP_ENTRIES
#define MAX_MAP_ENTRIES 1024
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(stat_t));
    __uint(max_entries, MAX_MAP_ENTRIES);
} ul_stat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(stat_t));
    __uint(max_entries, MAX_MAP_ENTRIES);
} dl_stat SEC(".maps");


static __always_inline stat_t * get_dl_stat(__u16 id) {
    __u16 key = id;
    return map_lookup_elem(&dl_stat, &key);
}

static __always_inline  stat_t * get_ul_stat(__u16 id) {
    __u16 key = id;
    return map_lookup_elem(&ul_stat, &key);
}


#endif /* __LINUX_STAT_H__ */