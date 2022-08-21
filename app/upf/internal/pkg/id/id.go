package id

import (
	"fmt"
	"net"
)

type SEID uint64

type TEID uint32

type UEIP []byte

func (s SEID) String() string {
	return fmt.Sprintf("S%d", s)
}

func (u UEIP) String() string {
	return fmt.Sprintf("IP%s", net.IP(u))
}

func (t TEID) String() string {
	return fmt.Sprintf("T%d", t)
}
