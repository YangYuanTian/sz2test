package n4layer

import (
	"container/list"
	"errors"
	"github.com/intel-go/nff-go/types"
	"strings"
	"sync"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/rlogger"
)

const moduleTag rlogger.ModuleTag = "n4layer"

// buffer size
const (
	buffer_CHAN_CAP = 1000 // rawsocket receive channel buffer
)

var SequenceNumber uint32 = 1

var UpfN4Layer N4Layer = N4Layer{BufferMsg: make(chan []byte, buffer_CHAN_CAP)}

type N4Layer struct {
	UpfIp     string // 用于本地节点标识
	N3Ip      string
	N3Ipv6    string
	BufferMsg chan []byte // 用于传递缓存的数据
}

// 发送buffer引用到sendingList, 最大长度是N4Cxt的长度
type SendList struct {
	Rw       sync.RWMutex
	State    chan struct{}
	SendList *list.List
}

var SendingList SendList = SendList{State: make(chan struct{}, 1), SendList: list.New()}
var PasUpfTable PasUpfTableMap

type PasUpfTableMap struct {
	sync.Map
}

// 储存 key--DNN value--PasUpf
func StorePasUpf(dnn string, pasUpf *pfcp.IEFTEID) error {
	if dnn == "" {
		return errors.New("dnn is null value")
	}
	if pasUpf == nil {
		return errors.New("pasUpf is nil")
	}
	PasUpfTable.Store(dnn, pasUpf)
	return nil
}
func DeletePasUpf(dnn string) error {
	if dnn == "" {
		return errors.New("delete failed,the dnn is null value")
	}
	_, l := PasUpfTable.LoadAndDelete(dnn)
	if !l {
		return errors.New("delete failed,the dnn is not exist")
	}
	return nil
}

// 遍历表中值ipv4
func RangePasUpf(v types.IPv4Address) (ret bool) {
	PasUpfTable.Range(func(key, value interface{}) bool {
		if strings.Contains(v.String(), value.(*pfcp.IEFTEID).IPv4Addr.To4().String()) {
			ret = true
			return false
		}
		//fmt.Println(key,value)
		return true
	})
	return
}

// 遍历表中值ipv6
func RangePasUpfIpv6(v types.IPv6Address) (ret bool) {
	PasUpfTable.Range(func(key, value interface{}) bool {
		if strings.Contains(v.String(), value.(*pfcp.IEFTEID).IPv6Addr.To16().String()) {
			ret = true
			return false
		}
		//fmt.Println(key,value)
		return true
	})
	return
}

// 表的长度
func LenPasUpfTable() uint32 {
	length := uint32(0)
	PasUpfTable.Range(func(key, value interface{}) bool {
		length += 1
		return true
	})
	return length
}
func PasUpfTableIsExist(dnn string) bool {
	_, ok := PasUpfTable.Load(dnn) // true is exist
	return ok
}
func ValuePasUpfTable(dnn string) *pfcp.IEFTEID {
	v, _ := PasUpfTable.Load(dnn) // true is exist
	return v.(*pfcp.IEFTEID)
}
