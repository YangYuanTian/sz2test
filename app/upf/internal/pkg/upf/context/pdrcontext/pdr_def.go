package pdrcontext

import (
	"errors"
	flowT "github.com/intel-go/nff-go/types"
	"net"
	"sort"
	"sync"
	"upf/internal/pkg/cmn/message/gtpv1u"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types3gpp"
)

const moduleTag rlogger.ModuleTag = "pdrcontext"

// Data flow context
type DataFlowContext struct {
	SEID            uint64
	RuleID          uint16
	UEIP            net.IP
	UEPort          int
	GnbTEID         types3gpp.Teid // 在N4 modify 的FAR中提供 OuterHeaderCreation
	GnbIP           net.IP
	UpfIP           net.IP
	UpfTEID         types3gpp.Teid // 在N4 establish 的PDR中提供 LocalFTEID
	OuterHeaderDesc uint16
	DnIp            []byte
	DNIPv4          flowT.IPv4Address
	UP              gtpv1u.ULPDUSession //QFI
	DP              gtpv1u.DLPDUSession
	GtpMsg          *gtpv1u.N3MsgParser

	UEIpType uint16

	NoNeedCap bool

	Rw sync.RWMutex
}

/// types.IGetAMFTraceFunc
/*func (p *DataFlowContext) ConstructUPFTraceObj() interface{} {
	if p == nil {
		return nil
	}

	traceObj := rlogger.CreateUPFTraceValueCtxt()
	traceObj.UPFSEID = types.Uint64Valid{V: p.SEID, Valid: true}
	return traceObj
}*/

// todo: UE 发起多个session时，从UE IP地址过滤，不能区分不同的session。
// Core分配的UE IP在每个session中不同来保证。

// 存储N6侧的过滤规则
type CorePDRs struct {
	CorePdrs []CorePDR
}

//CorePDRs()

type CorePDR struct {
	SEID         uint64
	QFI          uint8
	UpfTEID      types3gpp.Teid
	UpfIpAddress net.IP
	GnbTEID      types3gpp.Teid
	GnbIpAddress net.IP
	PDR          *pfcp.IECreatePDR
	UEIPAddress  net.IP
}

// 当前应用一个优先级最高的PDR
// PDRs按照优先级排序
func CorePDRsSort(pdrs CorePDRs) error {
	sort.Slice(pdrs.CorePdrs, func(i, j int) bool {
		return pdrs.CorePdrs[i].PDR.Precedence.PrecedenceValue <
			pdrs.CorePdrs[j].PDR.Precedence.PrecedenceValue
	})
	return nil
}

// 获取一个UEIPaddress匹配的PDR
// match fields,规则：core侧有UEIP
func GetUEIPCanMatchPDR(pdrs CorePDRs) (pdr *CorePDR) {
	// 如果PDI中有多个匹配字段，取仅有UEIPaddress字段的PDR
	for _, v := range pdrs.CorePdrs {
		if v.PDR.PDI.UEIPaddress != nil {
			//v.PDR.PDI.ApplicationID == nil && v.PDR.PDI.SDFFilters == nil
			pdr = &v
			return pdr
		}
	}
	return nil
}

// 根据获取的PDR构造N6侧下行过滤规则
func SetCorePDRTable(pdr *CorePDR) error {
	if pdr == nil {
		//rlogger.Trace(moduleTag, types.ERROR, nil,  "Input parameter check failed")
		return errors.New("Input parameter check failed")
	}
	if len(pdr.UEIPAddress.String()) == 0 {
		return errors.New("Input parameter check failed")
	}
	IptoPDRTable.Set(pdr.UEIPAddress.String(), pdr)
	return nil
}

// ----------------------------------------------------------------------------
// 存储N3侧的过滤规则
// ----------------------------------------------------------------------------
type AccessPDRs struct {
	AccessPdrs []AccessPDR
}
type AccessPDR struct {
	SEID         uint64
	QFI          uint8
	UpfTEID      types3gpp.Teid
	UpfIpAddress net.IP
	PDR          *pfcp.IECreatePDR
	UEIPAddress  net.IP
}

// 当前应用一个优先级最高的PDR
// PDRs按照优先级排序
func AccessPDRsSort(pdrs AccessPDRs) error {
	sort.Slice(pdrs.AccessPdrs, func(i, j int) bool {
		return pdrs.AccessPdrs[i].PDR.Precedence.PrecedenceValue <
			pdrs.AccessPdrs[j].PDR.Precedence.PrecedenceValue
	})
	return nil
}

// 获取一个TEID匹配的PDR
// match fields,规则：access侧有LocalFTEID && SDFFilters
func GetPDRmatchingTEID(pdrs AccessPDRs) (pdr *AccessPDR) {
	// 如果PDI中有多个匹配字段，取仅有TEID&&SDFFilters字段的PDR
	for _, v := range pdrs.AccessPdrs {
		//fmt.Println("GetPDRmatchingTEID:", v)
		if v.PDR.PDI.LocalFTEID != nil &&
			//v.PDR.PDI.ApplicationID == nil &&
			v.PDR.PDI.SDFFilters != nil {
			pdr = &v
			return pdr
		}

	}
	return nil
}

// 根据获取的PDR构造N3侧下行过滤规则
func SetAccessPDRTable(pdr *AccessPDR) error {
	if pdr == nil {
		//rlogger.Trace(moduleTag, types.ERROR, nil,  "Input parameter check failed")
		return errors.New("Input parameter check failed")
	}
	//fmt.Println(pdr)
	//fmt.Println(pdr.UpfTEID)
	err := TeidtoPDRTable.Set(uint32(pdr.UpfTEID), pdr)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "TeidtoPDRTable error：%s", err)
	}
	rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "TeidtoPDRTable length:%d", TeidtoPDRTable.Length())

	return nil
}
