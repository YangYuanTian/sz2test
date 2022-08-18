#ifndef __LIB_USER_H_
#define __LIB_USER_H_

typedef struct {
    /*
        __u8  drop;
        __u8  pass;
        __u8  flow_control;
        __u8  desc;
        __u16 stat_id;
    */
    __u64 flags;
} usr_ctx_uplink_t;



#define IP_START 0
#define UDP_START 20
#define GTP_START 28
#define EXTENT_HEADER_START 40

#define DROP(x) ((x>>56) & 0xff)
#define PASS(x) ((x>>48) & 0xff)
#define FLOW_CONTROL(x) ((x>>40) & 0xff)
#define DESC(x) ((x>>32) & 0xff)
#define STAT_ID(x) ((x>>16) & 0xffff)

typedef struct {

    char template[48];

    /*
        __u8 drop;
        __u8 pass;
        __u8 flow_control;
        __u8 desc;
        __u16 stat_id;
    */
    __u64 flags;

} usr_ctx_downLink_t;



/* Define  hash maps for storing forward rule */
struct {
   __uint(type, BPF_MAP_TYPE_HASH);  // BPF map 类型
    __type(key, __u32);              // teid
    __type(value, usr_ctx_downLink_t);       // 用户上下文
    __uint(max_entries, MAX_MAP_ENTRIES);        // 最大 entry 数量
} n4_ueip_map __section(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, usr_ctx_uplink_t);
    __uint(max_entries, MAX_MAP_ENTRIES);
} n4_teid_map __section(".maps");

static __always_inline usr_ctx_downLink_t * get_user_ctx_by_ueip_v4(__u32* ueip)
{
    return map_lookup_elem(&n4_ueip_map, ueip);
}

static __always_inline usr_ctx_uplink_t * get_user_ctx_by_teid(__u32* teid)
{
    return map_lookup_elem(&n4_teid_map, teid);
}

#endif /* __LIB_USER_H_ */