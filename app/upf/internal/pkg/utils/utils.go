package utils

import "net"

func SwapUint32(u uint32) uint32 {
	return (u << 24) | ((u << 8) & 0x00FF0000) | ((u >> 8) & 0x0000FF00) | (u >> 24)
}

func SwapUint64(u uint64) uint64 {
	return (u << 56) | ((u << 40) & 0x00FF000000000000) | ((u << 24) & 0x0000FF0000000000) | ((u << 8) & 0x000000FF00000000) | ((u >> 8) & 0x00000000FF000000) | ((u >> 24) & 0x0000000000FF0000) | ((u >> 40) & 0x000000000000FF00) | (u >> 56)
}

func Bool2byte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func KeyOfUEIP(ip net.IP) uint32 {
	return uint32(ip[3])<<24 | uint32(ip[2])<<16 | uint32(ip[1])<<8 | uint32(ip[0])
}
