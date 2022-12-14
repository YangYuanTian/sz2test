// +build ignore

#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#define SEC(name)                                                              \
  _Pragma("GCC diagnostic push")                                               \
      _Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")               \
          __attribute__((section(name), used)) _Pragma("GCC diagnostic pop")

#define arpNeighNotFound 1
#define ul_findRule 2
#define dl_findRule 3
#define gtpSignalling 4

#include <bpf/ctx/xdp.h>

#include "node_config.h"

#include <bpf/api.h>
#include <bpf/helpers.h>
#include <bpf/types_mapper.h>
#include <lib/eth.h>
#include <linux/in.h>
#include <linux/ip.h>

#include "filter.h"
#include "gtpu.h"
#include "route.h"
#include "stat.h"
#include "tools.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#ifndef REMOVE_GTP_UDP_IP
#define REMOVE_GTP_UDP_IP 2
#endif

#define ETHLEN 14
#define IPv4LEN 20
#define IPv6LEN 40
#define UDPLEN 8
#define GTPUHDRLEN 8

// n6入口处理程序
SEC("xdp/n6") int xdp_prog_func_n6(struct xdp_md *ctx) {
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

  __be16 id = ipv4_hdr->id;
  // 收包打点
  __u64 ind = usr->flags;
  stat_t *stat = get_dl_stat(STAT_ID(ind));
  if (stat) {
    stat->total_received_packets++;
    stat->total_received_bytes += (ctx->data_end - ctx->data);
  }

  // 如果上下文指示把数据包直接透传，则把数据包传递到用户态
  if (PASS(ind)) {
    set_packet_type(ctx, ul_findRule, PASS(ind));
    return XDP_PASS;
  }

  // 如果指示丢包，则直接把包丢弃
  if (DROP(ind)) {
    return XDP_DROP;
  }

  // 如果上下文指示流控，执行流控操作
  //    next = flow_control(FLOW_CONTROL(ind),ipv4_hdr.id);
  //    if (next != GO_ON)
  //        return next;

  // 如果指示对数据包的操作是增加GTP/UDP/IP包头，则执行加包头操作
  if (DESC(ind) == ADD_GTP_UDP_IP) {

    __le16 data_len = ctx->data_end - ctx->data;

    int num = HEADER_LEN(ind);

    if (num > 48 || num <= 0)
      return XDP_DROP;

    // 申请空间
    if (num == 0 || xdp_adjust_head(ctx, num))
      return XDP_DROP;

    char *data = ctx_data(ctx);
    char *data_end = ctx_data_end(ctx);
    char *copy_start = data + sizeof(struct ethhdr);

    if (ctx_no_room(copy_start + 48, data_end))
      return XDP_DROP;

    // 拷贝模板
    switch (num) {
    case 48:
      __bpf_memcpy(copy_start, usr->template, 48);
      break;
    case 44:
      __bpf_memcpy(copy_start, usr->template, 44);
      break;
    default:
      return XDP_DROP;
    }

    if (ctx_no_room(data + num + sizeof(struct ethhdr), data_end))
      return XDP_DROP;

    // 配置ipv4 header中的packet id
    struct iphdr *hdr = (struct iphdr *)(&data[sizeof(struct ethhdr)]);

    hdr->id = id;

    // 修正IP报头的长度
    hdr->tot_len = bpf_htons(ctx->data_end - ctx->data - ETHLEN);

    // 修正udp报头的长度
    struct udphdr *udp =
        (struct udphdr *)(&data[sizeof(struct ethhdr) + sizeof(struct iphdr)]);
    udp->len = bpf_htons(ctx->data_end - ctx->data - sizeof(struct ethhdr) -
                         sizeof(struct iphdr));

    // 修正gtp报头的长度
    struct gtphdr *gtp = (struct gtphdr *)(&data[ETHLEN + IPv4LEN + UDPLEN]);
    gtp->length = bpf_htons(data_len + num - 8 - 20 - 8);

    int next = redirect_direct_v4(ctx, hdr);

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

// n3入口处理程序
SEC("xdp/n3") int xdp_prog_func_n3(struct xdp_md *ctx) {
  // N3 包过滤，保证传递进来的是一个用户转发的GTP数据包
  int next = n3_packet_filter(ctx);
  if (next != GO_ON)
    return next;

  // 解析GTP包的teid,并且把信令相关的包丢向内核
  __u32 teid;
  next = parse_teid_and_check_signalling(ctx, &teid);

  if (next == XDP_PASS)
    set_packet_type(ctx, gtpSignalling, 0);

  if (next != GO_ON)
    return next;

  // 通过teid 查找用户上下文
  usr_ctx_uplink_t *usr = get_user_ctx_by_teid(&teid);

  if (!usr) {
    return XDP_DROP;
  }

  // 收包打点
  __u64 ind = usr->flags;

  stat_t *stat = get_ul_stat(STAT_ID(ind)); //
  if (stat) {
    stat->total_received_packets++;
    stat->total_received_bytes += (ctx->data_end - ctx->data);
  }

  // 如果上下文指示把数据包直接透传，则把数据包传递到用户态
  if (PASS(ind)) {
    set_packet_type(ctx, ul_findRule, PASS(ind));
    return XDP_PASS;
  }

  // 如果指示丢包，则直接把包丢弃
  if (DROP(ind)) {
    return XDP_DROP;
  }

  // 如果指示对数据包的操作是去掉GTP/UDP/IP包头，则执行去包头操作
  if (DESC(ind) == REMOVE_GTP_UDP_IP) {

    int len = gtp_udp_ip_header_len(ctx);

    //    移除偏移长度
    if (len == 0 || xdp_adjust_head(ctx, -len))
      return XDP_DROP;

    void *data = ctx_data(ctx);
    void *data_end = ctx_data_end(ctx);

    if (ctx_no_room(data + sizeof(struct ethhdr) + sizeof(struct iphdr),
                    data_end)) {
      return XDP_DROP;
    }

    struct iphdr *ipv4_hdr = (struct iphdr *)(&data[sizeof(struct ethhdr)]);

    next = redirect_direct_v4(ctx, ipv4_hdr);

    if (next == XDP_TX || next == XDP_REDIRECT) {
      //   发包打点
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

// 如果n3 与 n6共用同一张网卡的时候
SEC("xdp/n3n6") int xdp_prog_func_n3n6(struct xdp_md *ctx) {

  // 只处理IP数据包
  struct iphdr *ipv4_hdr = parse_ipv4(ctx);
  int next = XDP_PASS;
  struct udphdr *udp_hdr;

  if (!ipv4_hdr)
    return XDP_PASS;

  // 检查目的IP地址，如果是目的地址是本机，则直接把数据包丢往内核
  __u32 port = 0;
  config *my_config = get_port_config(&port);
  if (!my_config || ipv4_hdr->daddr == my_config->ipv4_self)
    goto N3;

  // 通过ueip 查找用户上下文
  usr_ctx_downLink_t *usr = get_user_ctx_by_ueip_v4(&ipv4_hdr->daddr);

  // 如果没有查找到上下文，则直接把数据包丢弃
  if (!usr) {
    return XDP_DROP;
  }

  __be16 id = ipv4_hdr->id;
  // 收包打点
  __u64 ind = usr->flags;
  stat_t *stat = get_dl_stat(STAT_ID(ind));
  if (stat) {
    stat->total_received_packets++;
    stat->total_received_bytes += (ctx->data_end - ctx->data);
  }

  // 如果上下文指示把数据包直接透传，则把数据包传递到用户态
  if (PASS(ind)) {
    set_packet_type(ctx, ul_findRule, PASS(ind));
    return XDP_PASS;
  }

  // 如果指示丢包，则直接把包丢弃
  if (DROP(ind)) {
    return XDP_DROP;
  }

  // 如果上下文指示流控，执行流控操作
  //    next = flow_control(FLOW_CONTROL(ind),ipv4_hdr.id);
  //    if (next != GO_ON)
  //        return next;

  // 如果指示对数据包的操作是增加GTP/UDP/IP包头，则执行加包头操作
  if (DESC(ind) == ADD_GTP_UDP_IP) {

    __le16 data_len = ctx->data_end - ctx->data;

    int num = HEADER_LEN(ind);

    if (num > 48 || num <= 0)
      return XDP_DROP;

    // 申请空间
    if (xdp_adjust_head(ctx, -num))
      return XDP_DROP;

    char *data = ctx_data(ctx);
    char *data_end = ctx_data_end(ctx);
    char *copy_start = data + sizeof(struct ethhdr);

    if (ctx_no_room(copy_start + 48, data_end))
      return XDP_DROP;

    // 拷贝模板
    switch (num) {
    case 48:
      __bpf_memcpy(copy_start, usr->template, 48);
      break;
    case 44:
      __bpf_memcpy(copy_start, usr->template, 44);
      break;
    default:
      return XDP_DROP;
    }

    struct ethhdr *eth = (struct ethhdr *)data;
    eth->h_proto = ETH_P_IP_SWAPPED;

    // 配置ipv4 header中的packet id
    struct iphdr *hdr = (struct iphdr *)(&data[sizeof(struct ethhdr)]);

    hdr->id = id;

    // 修正IP报头的长度
    hdr->tot_len = bpf_htons(ctx->data_end - ctx->data - ETHLEN);

    // 修正udp报头的长度
    struct udphdr *udp =
        (struct udphdr *)(&data[sizeof(struct ethhdr) + sizeof(struct iphdr)]);
    udp->len = bpf_htons(ctx->data_end - ctx->data - sizeof(struct ethhdr) -
                         sizeof(struct iphdr));

    // 修正gtp报头的长度
    struct gtphdr *gtp = (struct gtphdr *)(&data[ETHLEN + IPv4LEN + UDPLEN]);
    gtp->length = bpf_htons(data_len + num - 8 - 20 - 8);

    int next = redirect_direct_v4(ctx, hdr);

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

N3:
  // N3 包过滤，保证传递进来的是一个用户转发的GTP数据包
  udp_hdr = (struct udphdr *)(ipv4_hdr + 1);

  // 不是ipv4的包，或者不是udp的包，过滤掉
  if (ipv4_hdr->protocol != IPPROTO_UDP)
    return XDP_PASS;

  if (check_udp_gtp_port(udp_hdr, ctx))
    return XDP_PASS;

  // 解析GTP包的teid,并且把信令相关的包丢向内核
  __u32 teid = 0;
  next = parse_teid_and_check_signalling(ctx, &teid);

  if (next == XDP_PASS)
    set_packet_type(ctx, gtpSignalling, 0);

  if (next != GO_ON)
    return next;

  // 通过teid 查找用户上下文
  usr_ctx_uplink_t *usr_ul = get_user_ctx_by_teid(&teid);

  if (!usr_ul) {
    return XDP_DROP;
  }

  // 收包打点
  __u64 ind_ul = usr_ul->flags;

  stat_t *stat_ul = get_ul_stat(STAT_ID(ind_ul)); //
  if (stat_ul) {
    stat_ul->total_received_packets++;
    stat_ul->total_received_bytes += (ctx->data_end - ctx->data);
  }

  // 如果上下文指示把数据包直接透传，则把数据包传递到用户态
  if (PASS(ind_ul)) {
    set_packet_type(ctx, ul_findRule, PASS(ind_ul));
    return XDP_PASS;
  }

  // 如果指示丢包，则直接把包丢弃
  if (DROP(ind_ul)) {
    return XDP_DROP;
  }

  // 如果指示对数据包的操作是去掉GTP/UDP/IP包头，则执行去包头操作
  if (DESC(ind_ul) == REMOVE_GTP_UDP_IP) {

    int len = gtp_udp_ip_header_len(ctx);

    //    移除偏移长度
    if (len == 0 || xdp_adjust_head(ctx, len))
      return XDP_DROP;

    void *data = ctx_data(ctx);
    void *data_end = ctx_data_end(ctx);

    if (ctx_no_room(data + sizeof(struct ethhdr) + sizeof(struct iphdr),
                    data_end)) {
      return XDP_DROP;
    }

    // 恢复eth头
    struct ethhdr *eth = (struct ethhdr *)data;
    eth->h_proto = ETH_P_IP_SWAPPED;

    struct iphdr *ipv4_hdr = (struct iphdr *)(&data[sizeof(struct ethhdr)]);

    next = redirect_direct_v4(ctx, ipv4_hdr);

    if (next == XDP_TX || next == XDP_REDIRECT) {
      //   发包打点
      if (stat_ul) {
        stat_ul->total_forward_packets++;
        stat_ul->total_forward_bytes += (ctx->data_end - ctx->data);
      }
    }

    return next;
  }

  // 不支持的操作，直接把数据包丢弃
  return XDP_DROP;
}