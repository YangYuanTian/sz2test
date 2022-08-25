package utils

import (
	"github.com/pkg/errors"
	"net"
	"strings"
)

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

func GetNicIpByName(iFaceName string) (net.IP, error) {

	nic, err := net.InterfaceByName(iFaceName)

	if err != nil {
		return nil, err
	}

	addr, err := nic.Addrs()
	if err != nil {
		return nil, err
	}

	if len(addr) < 1 {
		return nil, errors.New("ip addr not found with" + nic.Name)
	}

	ipStr := addr[0].String()

	if strings.Contains(ipStr, "/") {
		ipStr = strings.Split(ipStr, "/")[0]
	}

	if strings.Contains(ipStr, ":") {
		ipStr, _, err = net.SplitHostPort(ipStr)
		if err != nil {
			return nil, err
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, errors.New("parse ip failed")
	}

	if ip.To4() == nil {
		return nil, errors.New("not a ipv4 addr")
	}

	ip = ip.To4()

	return ip, nil
}
