#ifndef __LIB_ROUTE_H_
#define __LIB_ROUTE_H_

#include "tools.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IP_DF
#define IP_DF 0x4000
#endif

#define DROP_UNUSED1		-130 /* unused */
#define DROP_UNUSED2		-131 /* unused */
#define DROP_INVALID_SIP	-132
#define DROP_POLICY		-133
#define DROP_INVALID		-134
#define DROP_CT_INVALID_HDR	-135
#define DROP_FRAG_NEEDED	-136
#define DROP_CT_UNKNOWN_PROTO	-137
#define DROP_UNUSED4		-138 /* unused */
#define DROP_UNKNOWN_L3		-139
#define DROP_MISSED_TAIL_CALL	-140
#define DROP_WRITE_ERROR	-141
#define DROP_UNKNOWN_L4		-142
#define DROP_UNKNOWN_ICMP_CODE	-143
#define DROP_UNKNOWN_ICMP_TYPE	-144
#define DROP_UNKNOWN_ICMP6_CODE	-145
#define DROP_UNKNOWN_ICMP6_TYPE	-146
#define DROP_NO_TUNNEL_KEY	-147
#define DROP_UNUSED5		-148 /* unused */
#define DROP_UNUSED6		-149 /* unused */
#define DROP_UNKNOWN_TARGET	-150
#define DROP_UNROUTABLE		-151
#define DROP_UNUSED7		-152 /* unused */
#define DROP_CSUM_L3		-153
#define DROP_CSUM_L4		-154
#define DROP_CT_CREATE_FAILED	-155
#define DROP_INVALID_EXTHDR	-156
#define DROP_FRAG_NOSUPPORT	-157
#define DROP_NO_SERVICE		-158
#define DROP_UNUSED8		-159 /* unused */
#define DROP_NO_TUNNEL_ENDPOINT -160
#define DROP_NAT_46X64_DISABLED	-161
#define DROP_EDT_HORIZON	-162
#define DROP_UNKNOWN_CT		-163
#define DROP_HOST_UNREACHABLE	-164
#define DROP_NO_CONFIG		-165
#define DROP_UNSUPPORTED_L2	-166
#define DROP_NAT_NO_MAPPING	-167
#define DROP_NAT_UNSUPP_PROTO	-168
#define DROP_NO_FIB		-169
#define DROP_ENCAP_PROHIBITED	-170
#define DROP_INVALID_IDENTITY	-171
#define DROP_UNKNOWN_SENDER	-172
#define DROP_NAT_NOT_NEEDED	-173 /* Mapped as drop code, though drop not necessary. */
#define DROP_IS_CLUSTER_IP	-174
#define DROP_FRAG_NOT_FOUND	-175
#define DROP_FORBIDDEN_ICMP6	-176
#define DROP_NOT_IN_SRC_RANGE	-177
#define DROP_PROXY_LOOKUP_FAILED	-178
#define DROP_PROXY_SET_FAILED	-179
#define DROP_PROXY_UNKNOWN_PROTO	-180
#define DROP_POLICY_DENY	-181
#define DROP_VLAN_FILTERED	-182
#define DROP_INVALID_VNI	-183
#define DROP_INVALID_TC_BUFFER  -184
#define DROP_NO_SID		-185
#define DROP_MISSING_SRV6_STATE	-186

#define NAT_PUNT_TO_STACK	DROP_NAT_NOT_NEEDED
#define NAT_46X64_RECIRC	100



static __always_inline int redirect_direct_v4(struct __ctx_buff *ctx,
                                              struct iphdr *ip4) {
  int ret;

  struct bpf_fib_lookup fib_params = {
      .family = AF_INET,
      .ifindex = ctx->ingress_ifindex,
      .ipv4_src = ip4->saddr,
      .ipv4_dst = ip4->daddr,
  };

  ret = fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
  switch (ret) {
  case BPF_FIB_LKUP_RET_SUCCESS:
    break;
  case BPF_FIB_LKUP_RET_NO_NEIGH:
    set_packet_type(ctx, arpNeighNotFound, fib_params.ifindex);
    return XDP_PASS;
  default:
    return XDP_DROP;
  }

  if (eth_store_daddr(ctx, fib_params.dmac, 0) < 0)
    return XDP_DROP;
  if (eth_store_saddr(ctx, fib_params.smac, 0) < 0)
    return XDP_DROP;
  return ctx_redirect(ctx, fib_params.ifindex, 0);
}

#endif /* __LIB_ROUTE_H_ */