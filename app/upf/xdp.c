// +build ignore

#include <bpf/ctx/xdp.h>

#include "node_config.h"

#include <bpf/api.h>
#include <bpf/helpers.h>
#include <lib/eth.h>
#include <linux/in.h>
#include <linux/ip.h>

#include "filter.h"
#include "gtpu.h"
#include "route.h"
#include "stat.h"

char __license[] __section("license") = "Dual MIT/GPL";

#ifndef REMOVE_GTP_UDP_IP
#define REMOVE_GTP_UDP_IP 4
#endif

// n3入口处理程序
__section("xdp/n3") int xdp_prog_func_n3(struct xdp_md *ctx) {

  // N3 包过滤，保证传递进来的是一个用户转发的GTP数据包
  int next = n3_packet_filter(ctx);
  if (next != GO_ON)
    return next;

  // 解析GTP包的teid,并且把信令相关的包丢向内核
  __u32 teid;
  next = parse_teid_and_check_signalling(ctx, &teid);
  if (next != GO_ON)
    return next;

  // 通过teid 查找用户上下文
  usr_ctx_uplink_t *usr = get_user_ctx_by_teid(&teid);

  if (usr == NULL) {
    return XDP_DROP;
  }

  // 收包打点
  __u64 ind = usr->flags;
  __u16 key = STAT_ID(ind);

  stat_t *stat = map_lookup_elem(&ul_stat, &key); //
  if (stat) {
    stat->total_received_packets++;
    stat->total_received_bytes += (ctx->data_end - ctx->data);
  }

  // 如果指示丢包，则直接把包丢弃
  if (DROP(ind)) {
    return XDP_DROP;
  }

  // 如果上下文指示把数据包直接透传，则把数据包传递到用户态
  if (PASS(ind)) {
    return XDP_PASS;
  }

  // 如果指示对数据包的操作是去掉GTP/UDP/IP包头，则执行去包头操作
  if (DESC(ind) == REMOVE_GTP_UDP_IP) {

    remove_gtp_udp_ip_header(ctx, usr);

    char *data = ctx_data(ctx);
    struct iphdr *ipv4_hdr = (struct iphdr *)&data[14];

    next = redirect_direct_v4(ctx, ipv4_hdr);

    if (next == XDP_TX || next == XDP_REDIRECT) {
      // 发包打点
      if (stat) {
        stat->total_forward_packets++;
        stat->total_forward_bytes += (ctx->data_end - ctx->data);
      }
    }

    return next;
  }

  // 不支持的操作，直接把数据包丢弃
  return XDP_DROP;
}

// n6入口处理程序
__section("xdp/n6") int xdp_prog_func_n6(struct xdp_md *ctx) {

  // 只处理IP数据包
  struct iphdr *ipv4_hdr = parse_ipv4(ctx);

  if (!ipv4_hdr)
    return XDP_PASS;

  // 检查目的IP地址，如果是目的地址是本机，则直接把数据包丢往内核
  __u32 port = 1;
  config *my_config = get_port_config(&port);
  if (!my_config || ipv4_hdr->daddr == my_config->ipv4_self)
    return XDP_PASS;

  // 通过ueip 查找用户上下文
  usr_ctx_downLink_t *usr = get_user_ctx_by_ueip_v4(&ipv4_hdr->daddr);

  // 如果没有查找到上下文，则直接把数据包丢弃
  if (!usr) {
    return XDP_DROP;
  }

  // 收包打点
  __u64 ind = usr->flags;
  stat_t *stat = get_dl_stat(STAT_ID(ind));
  if (stat) {
    stat->total_received_packets++;
    stat->total_received_bytes += (ctx->data_end - ctx->data);
  }

  // 如果指示丢包，则直接把包丢弃
  if (DROP(ind)) {
    return XDP_DROP;
  }

  // 如果上下文指示把数据包直接透传，则把数据包传递到用户态
  if (PASS(ind)) {
    return XDP_PASS;
  }

  // 如果上下文指示流控，执行流控操作
  //    next = flow_control(FLOW_CONTROL(ind),ipv4_hdr.id);
  //    if (next != GO_ON)
  //        return next;

  // 如果指示对数据包的操作是增加GTP/UDP/IP包头，则执行加包头操作
  if (DESC(ind) == ADD_GTP_UDP_IP) {

    int next = add_gtp_header(ctx, usr, ipv4_hdr->id);

    if (next != GO_ON)
      return next;

    next = redirect_direct_v4(ctx, ipv4_hdr);

    if (next == XDP_TX || next == XDP_REDIRECT) {
      // 发包打点
      if (stat) {
        stat->total_forward_packets++;
        stat->total_forward_bytes += (ctx->data_end - ctx->data);
      }
    }

    return next;
  }

  return XDP_DROP;
}

// 如果n3 与 n6共用同一张网卡的时候
__section("xdp/n3n6") int xdp_prog_func_n3n6(struct xdp_md *ctx) {
  return XDP_PASS;
}