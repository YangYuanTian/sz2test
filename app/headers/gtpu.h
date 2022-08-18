#ifndef __LIB_GTPU_H_
#define __LIB_GTPU_H_


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
define	GTPU_ECHO_REQUEST  1
define	GTPU_ECHO_RESPONSE  2

define	GTPU_ERROR_INDICATION  26

define	GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION  31

define	GTPU_TUNNEL_STATUS  253
define	GTPU_END_MARKER  254
define	GTPU_G_PDU  255


static __always_inline int add_gtp_header(struct xdp_md *ctx,usr_ctx_downLink_t *usr,__u16 id) {

    /*
        首先判断需要添加多长的字节 需要添加一个GTP头，一个UDP头，一个IP头
        当然这些都存在模板中，所以只要申请空间，并把模板中的内容拷贝过去就可以了
    */

    __u8 l = usr->template[EXTENT_HEADER_START];

    if (l > 2)
        return XDP_DROP

    int num = length * 4 + 8 + 8 + 20;

    //申请空间
    if (xdp_adjust_head(ctx, num))
        return XDP_DROP;

    //拷贝模板
    if (xdp_store_bytes(ctx,ETH_HLEN,usr->template,num,0))
        return XDP_DROP;

    //gtp的下一扩展头为零，表示没有下一扩展头
    ctx.data[num+ETH_HLEN] = 0;

    //配置ipv4 header中的packet id
    struct iphdr* hdr = &ctx.data[ETH_HLEN]
    hdr->id = id;

    return GO_ON;
}




#endif /* __LIB_GTPU_H_ */