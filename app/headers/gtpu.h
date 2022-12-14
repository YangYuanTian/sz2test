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


static __always_inline int add_gtp_header_num(struct xdp_md *ctx,usr_ctx_downLink_t *usr,__u16 id) {

    /*
        ??????????????????????????????????????? ??????????????????GTP????????????UDP????????????IP???
        ????????????????????????????????????????????????????????????????????????????????????????????????????????????
    */

    __u8 l = usr->template[EXTENT_HEADER_START];
    char *data = ctx_data(ctx);
    char *data_end = ctx_data_end(ctx);

    if (l > 2)
        return 0;

    int num = l * 4 + 12 + 8 + 20;

    return num;
}



static __always_inline int gtp_udp_ip_header_len(struct xdp_md *ctx) {

    char *data = ctx_data(ctx);
    char *data_end = ctx_data_end(ctx);

    if (ctx_no_room(data+sizeof(struct ethhdr)+sizeof(struct iphdr),data_end))
        return 0;

    //??????ipv4 header?????????
    struct iphdr * ipv4hdr = (struct iphdr *)(&data[sizeof(struct ethhdr)]);

    int ip_len = ipv4hdr->ihl * 4;

    if (ip_len<20 || ip_len>60)
        return 0;

    int hlen = 14 + ip_len + 8;
    int num = ip_len + 8;

    if (ctx_no_room(data+hlen+8,data_end))
        return 0;

    //??????gtpu?????????
    if (data[hlen] & 0x07){
        num += 12;
        hlen += 12;

        if (ctx_no_room(data + hlen +1,data_end))
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

     // ??????gtp????????????????????????????????????
    if (gtp_hdr->message_type != GTPU_G_PDU)
        return XDP_PASS;

    *teid = gtp_hdr->teid;

    return GO_ON;
}


#endif /* __LIB_GTPU_H_ */