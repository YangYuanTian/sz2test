#ifndef __LIB_GTPU_H_
#define __LIB_GTPU_H_


#include <bpf/ctx/xdp.h>
#include "user.h"
#include <linux/if_ether.h>


#ifndef ADD_GTP_UDP_IP
#define ADD_GTP_UDP_IP 1
#endif

struct gtphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	PN:1,
	        S:1,
	        E:1,
	        _ignore:1,
	        PT:1,
		version:3;
#elif defined (__BIG_ENDIAN_BITFIELD)

           /*
                This field is used to determine the version of the GTP-U protocol.
                The version number shall be set to '1'
           */
	__u8	version:3,

	        /*
	            Protocol Type (PT): This bit is used as a protocol discriminator
	            between GTP (when PT is '1') and GTP' (when PT is '0')
	        */
	        PT:1,

	        _ignore:1,

	        /*
	          Extension Header flag (E)
            */
            E:1,

            /*
                Sequence Number flag (S)
            */
            S:1,

            /*
                N-PDU Number flag (PN)
            */
            PN:1;
#else
#error	"unknown bitfield endianness"
#endif
	__u8	message_type;

	/*
	    * The length field is the length of the entire GTP-U message, including the
        * fixed part of the header and the variable part of the header.
        * Length: This field indicates the length in octets of the payload, i.e.
        the rest of the packet following the mandatory part of the GTP header
        (that is the first 8 octets).
        The Sequence Number, the N-PDU Number
        or any Extension headers shall be considered to be part of the payload,
        i.e. included in the length count.
	*/
	__be16	length;

	__be32	teid;

	/*The options start here. */

	/*
	    Sequence Number: If Sequence Number field is used for G-PDUs (T-PDUs+headers),
        an increasing sequence number for T-PDUs is transmitted via GTP-U tunnels,
        when transmission order must be preserved.
        For Supported Extension Headers Notification and Error Indication messages,
        the Sequence Number shall be ignored by the receiver,
        even though the S flag is set to '1'.
	*/
	__be16	sequence_number;

	__u8	n_pdu_number;

	__u8	next_extension_header_type;
};


//Extension Header types
struct dl_pdu_extension_hdr {

       __u8	 length;  // total: 4 * length

#if defined(__LITTLE_ENDIAN_BITFIELD)
       __u8  spare_bit:1,
             MSNP:1,
             SNP:1,
             QMP:1,
             PDU_Type:4; //(=0)
       __u8  QoS_Flow_Identifier:6,
        	 RQI:1,
             PPP:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8 PDU_Type:4, //(=0)
         QMP:1,
         SNP:1,
         MSNP:1,
         spare_bit:1;
    __u8 PPP:1,
    	 RQI:1,
    	 QoS_Flow_Identifier:6;
#else
#error	"unknown bitfield endianness"
#endif
        __u8 PPI:3;
        __u8 spare1;
        __u8 spare2;
        __u8 spare3;
        __u8 next_extension_header_type;
};


//Message Types
#define	GTPU_ECHO_REQUEST  1
#define	GTPU_ECHO_RESPONSE  2

#define	GTPU_ERROR_INDICATION  26

#define	GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION  31

#define	GTPU_TUNNEL_STATUS  253
#define	GTPU_END_MARKER  254
#define	GTPU_G_PDU  255


static __always_inline int add_gtp_header(struct xdp_md *ctx,usr_ctx_downLink_t *usr,__u16 id) {

    /*
        首先判断需要添加多长的字节 需要添加一个GTP头，一个UDP头，一个IP头
        当然这些都存在模板中，所以只要申请空间，并把模板中的内容拷贝过去就可以了
    */

    __u8 l = usr->template[EXTENT_HEADER_START];
    char *data = ctx_data(ctx);
    char *data_end = ctx_data_end(ctx);

    if (l > 2)
        return XDP_DROP;

    int num = l * 4 + 12 + 8 + 20;

    //申请空间
    if (xdp_adjust_head(ctx, num) != 0)
        return XDP_DROP;

    //检查是否越界
    ctx_no_room(data+14+num,data_end);

    //拷贝模板
    switch(num){
        case 48:
            __bpf_memcpy(data+14,usr->template,48);
            break;
        case 44:
            __bpf_memcpy(data+14,usr->template,44);
            break;
        default:
            return XDP_DROP;
    }

    //gtp的下一扩展头为零，表示没有下一扩展头
    data[num+14] = 0;

    //配置ipv4 header中的packet id
    struct iphdr* hdr = (struct iphdr*)data[14];
    hdr->id = id;

    return GO_ON;
}



static __always_inline int gtp_udp_ip_header_len(struct xdp_md *ctx,usr_ctx_uplink_t* usr) {

    char *data = ctx_data(ctx);
    char *data_end = ctx_data_end(ctx);

    if (ctx_no_room(data+sizeof(struct ethhdr)+sizeof(struct iphdr),data_end))
        return 0;

    //获取ipv4 header的长度
    struct iphdr * ipv4hdr = (struct iphdr *)(&data[sizeof(struct ethhdr)]);

    int ip_len = ipv4hdr->ihl * 4;
    int hlen = 14 + ip_len + 8;
    int num = ip_len + 8;

    if (ctx_no_room(data+hlen,data_end))
        return 0;

    //获取gtpu的长度
    if (data[hlen] & 0x07){
        num += 12;
        hlen += 12;

        if (ctx_no_room(data + hlen,data_end))
            return 0;

        num += data[hlen] * 4;

    } else {
        num += 8;
    }

    return num;
}

static __always_inline int parse_teid_and_check_signalling(struct xdp_md *ctx,__u32 * teid) {

    char *data = ctx_data(ctx);
    char *data_end = ctx_data_end(ctx);

    if (ctx_no_room(data+50,data_end))
        return XDP_DROP;

    struct iphdr * ipv4hdr = (struct iphdr *)(&data[14]);
    int len = ipv4hdr->ihl * 4 + 8 + 14;

    if (ctx_no_room(data +len, data_end))
        return XDP_DROP;

    struct gtphdr *gtp_hdr = (struct gtphdr *)(&data[len]);

    if (ctx_no_room(gtp_hdr+1, data_end))
        return XDP_DROP;

     // 分离gtp中的控制信令包与数据流包
    if (gtp_hdr->message_type != GTPU_G_PDU)
        return XDP_PASS;

    *teid = gtp_hdr->teid;

    return GO_ON;
}


#endif /* __LIB_GTPU_H_ */