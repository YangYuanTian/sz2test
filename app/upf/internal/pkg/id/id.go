package id

import (
	"fmt"
	"net"
	"sync"
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

type statID struct {
	existed map[uint16]struct{}
	m       sync.Mutex
}

var allocId = statID{
	existed: make(map[uint16]struct{}),
}

// GetStatID always allocate a min and usable id
func GetStatID() uint16 {

	allocId.m.Lock()
	defer allocId.m.Unlock()

	var id uint16

	for x := uint16(1); x < ^uint16(0); x++ {
		if _, ok := allocId.existed[x]; !ok {
			id = x
			allocId.existed[id] = struct{}{}
		}
	}

	return id
}

type ID string

func (i ID) String() string {
	return string(i)
}
