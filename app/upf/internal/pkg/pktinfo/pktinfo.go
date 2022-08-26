package pktinfo

import "net"

type UlPkt struct {
	TEID     uint32
	SrcIp    net.IP
	SrcPort  int
	DstIp    net.IP
	DstPort  int
	Protocol byte
	//ip total length
	Length uint16
}

type DlPkt struct {
	SrcIp    net.IP
	SrcPort  int
	DstIp    net.IP
	DstPort  int
	Protocol byte
	//ip total length
	Length uint16
}
