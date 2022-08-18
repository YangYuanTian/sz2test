// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/api.h>
#include <bpf/ctx/unspec.h>

#include <node_config.h>

#include <linux/if_ether.h>

#define SKIP_CALLS_MAP 1
#define SKIP_POLICY_MAP 1

#define SOCKMAP 1

#include "../lib/common.h"
#include "../lib/eps.h"
#include "../lib/events.h"
#include "../lib/lb.h"
#include "../lib/maps.h"
#include "../lib/policy.h"

#include "bpf_sockops.h"

static __always_inline void sk_msg_extract4_key(const struct sk_msg_md *msg,
                                                struct sock_key *key) {
  key->dip4 = msg->remote_ip4;
  key->sip4 = msg->local_ip4;
  key->family = ENDPOINT_KEY_IPV4;

  key->sport = (bpf_ntohl(msg->local_port) >> 16);
  /* clang-7.1 or higher seems to think it can do a 16-bit read here
   * which unfortunately most kernels (as of October 2019) do not
   * support, which leads to verifier failures. Insert a READ_ONCE
   * to make sure that a 32-bit read followed by shift is generated.
   */
  key->dport = READ_ONCE(msg->remote_port) >> 16;
}

__section("sk_msg") int cil_redir_proxy(struct sk_msg_md *msg) {
  struct remote_endpoint_info *info;
  __u64 flags = BPF_F_INGRESS;
  struct sock_key key = {};
  __u32 dst_id = 0;
  int verdict;

  sk_msg_extract4_key(msg, &key);

  /* Currently, pulling dstIP out of endpoint
   * tables. This can be simplified by caching this information with the
   * socket to avoid extra overhead. This would require the agent though
   * to flush the sock ops map on policy changes.
   */
  info = lookup_ip4_remote_endpoint(key.dip4);
  if (info != NULL && info->sec_label)
    dst_id = info->sec_label;
  else
    dst_id = WORLD_ID;

  verdict = policy_sk_egress(dst_id, key.sip4, (__u16)key.dport);
  if (verdict >= 0)
    msg_redirect_hash(msg, &SOCK_OPS_MAP, &key, flags);
  return SK_PASS;
}

BPF_LICENSE("Dual BSD/GPL");
int _version __section("version") = 1;