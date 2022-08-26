package pdr

import (
	"net"
	"strings"
)

// matcher represents the matching rule for a given value
type matcher interface {
	// match returns true if the host and optional port or ip and optional port
	// are allowed
	match(host, port string, ip net.IP) bool
}

// allMatch matches on all possible inputs
type AllMatch struct{}

func (a AllMatch) match(host, port string, ip net.IP) bool {
	return true
}

type CidrMatch struct {
	cidr *net.IPNet
}

func (m CidrMatch) match(host, port string, ip net.IP) bool {
	return m.cidr.Contains(ip)
}

type IpMatch struct {
	ip   net.IP
	port string
}

func (m IpMatch) match(host, port string, ip net.IP) bool {
	if m.ip.Equal(ip) {
		return m.port == "" || m.port == port
	}
	return false
}

type DomainMatch struct {
	host string
	port string

	matchHost bool
}

func (m DomainMatch) match(host, port string, ip net.IP) bool {
	if strings.HasSuffix(host, m.host) || (m.matchHost && host == m.host[1:]) {
		return m.port == "" || m.port == port
	}
	return false
}
