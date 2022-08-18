// +build ignore

#include <bpf/ctx/xdp.h>

#include "node_config.h"

#include <bpf/api.h>
#include <bpf/helpers.h>
#include <linux/ip.h>
#include <linux/in.h>

#include "route.h"
#include "gtpu.h"
#include "stat.h"
#include <lib/eth.h>

char __license[] __section("license") = "Dual MIT/GPL";


//n3入口处理程序
SEC("xdp/n3")
int xdp_prog_func_n3(struct xdp_md *ctx) {

    //N3 包过滤，保证传递进来的是一个用户转发的GTP数据包
    struct iphdr *ipv4_hdr;
    int next = n3_packet_filter(ctx,&ipv4_hdr);
    if (next != GO_ON)
        return next;

    //解析GTP包的teid
    struct gtphdr *gtp;
    next = parse_gtphdr(ctx,&gtp);
    if (next != GO_ON)
        return next;

    //分离gtp中的控制信令包与数据流包
    if (is_signalling(gtp)){

        return XDP_PASS;
    }

    //通过teid 查找用户上下文
    usr_ctx_uplink_t * usr = get_user_ctx_by_teid(teid);

    //如果没有查找到上下文，或者是上下文指示把数据包丢弃，则直接把数据包丢弃
    if (!usr || usr.drop) {
        return XDP_DROP;
    }

    //如果上下文指示把数据包直接透传，则把数据包传递到用户态
    if (usr.pass) {
        return XDP_PASS;
    }

    //如果上下文指示流控，执行流控操作
//    next = flow_control(usr.flow_control,ipv4_hdr.id);
//    if (next != GO_ON)
//        return next;

    //如果指示对数据包的操作是去掉GTP/UDP/IP包头，则执行去包头操作
    if (usr.desc == REMOVE_GTP_UDP_IP){

        remove_gtp_header(ctx,usr);

        //将这个包从另一个网口中发送出去,发送之前需要进行查找路由表的操作
        //在这里定义一些操作码，如果mac不存在，需要透传到用户态。
        return redirect_direct_v4(ctx, ipv4_hdr);
    }

    //不支持的操作，直接把数据包丢弃
    return XDP_DROP;
}



//n6入口处理程序
SEC("xdp/n6")
int xdp_prog_func_n6(struct xdp_md *ctx) {

    struct iphdr *ipv4_hdr = parse_ipv4(ctx);

    if (!ipv4_hdr)
        return XDP_PASS;

    __u32 index = 1;
    config *my_config = map_lookup_elem(&config_route, &index);
    if (!my_config || ipv4_hdr->daddr == my_config->ipv4_self)
        return NULL;

    //通过ueip 查找用户上下文
    usr_ctx_downLink_t * usr = get_user_ctx_by_ueip_v4(iphdr.daddr);

    //如果没有查找到上下文，或者是上下文指示把数据包丢弃，则直接把数据包丢弃
    if (!usr) {
        return XDP_DROP;
    }

    //收包打点
    __u64 ind = usr->flags;
    stat_t *stat = get_dl_stat(STAT_ID(ind));
    stat->total_received_packets ++;
    stat->total_received_bytes += (ctx.data_end - ctx.data);

    if (DROP(ind)){
        return XDP_DROP;
    }

    //如果上下文指示把数据包直接透传，则把数据包传递到用户态
    if (PASS(ind)) {
        return XDP_PASS;
    }

    //如果上下文指示流控，执行流控操作
//    next = flow_control(usr.flow_control,ipv4_hdr.id);
//    if (next != GO_ON)
//        return next;

    //如果指示对数据包的操作是增加GTP/UDP/IP包头，则执行加包头操作
    if (DESC(ind) == ADD_GTP_UDP_IP){

        next = add_gtp_header(ctx,usr,ipv4_hdr->id);

        if (next != GO_ON)
            return next;

        next = redirect_direct_v4(ctx, ipv4_hdr);
        if (next == XDP_TX || next == XDP_REDIRECT){
            //发包打点
            stat->total_sent_packets ++;
            stat->total_sent_bytes += (ctx.data_end - ctx.data);
        }
        return next;
    }

    return XDP_DROP;
}

//如果n3 与 n6共用同一张网卡的时候
SEC("xdp/n3n6")
int xdp_prog_func_n3n6(struct xdp_md *ctx) {
    return XDP_PASS;
}