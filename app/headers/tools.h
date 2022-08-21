#ifndef __LIB_TOOL_H_
#define __LIB_TOOL_H_

static __always_inline set_packet_type(struct xdp_md *ctx, __u8 type, __u8 index)
{
     char *data = ctx_data(ctx);
     char *data_end = ctx_data_end(ctx);

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    data[0] = type;
    data[1] = index;
}



#endif /* __LIB_USER_H_ */