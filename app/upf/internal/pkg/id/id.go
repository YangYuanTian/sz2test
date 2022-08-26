package id

import (
	"fmt"
	"github.com/gogf/gf/v2/errors/gerror"
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
	max     uint16
}

func SetMaxID(u uint16) {
	allocId.max = u
}

var allocId = statID{
	existed: make(map[uint16]struct{}),
}

// GetStatID always allocate a min and usable id
func GetStatID() (uint16, error) {

	allocId.m.Lock()
	defer allocId.m.Unlock()

	var id = -1

	for x := uint16(1); x < allocId.max; x++ {
		if _, ok := allocId.existed[x]; !ok {
			id = int(x)
			allocId.existed[x] = struct{}{}
		}
	}

	if id == -1 {
		return 0, gerror.Newf("not available stat id for max id value:%d", allocId.max)
	}

	return uint16(id), nil
}

type ID string

func (i ID) String() string {
	return string(i)
}

func StatIDReturn(id uint16) {

	allocId.m.Lock()
	defer allocId.m.Unlock()

	delete(allocId.existed, id)
}
