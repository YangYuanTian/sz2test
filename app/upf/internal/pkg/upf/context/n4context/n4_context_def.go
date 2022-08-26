package n4context

import (
	"container/list"
	"net"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/message/pfcp/utils/tools"
	"upf/internal/pkg/cmn/metric"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types3gpp"
	"upf/internal/pkg/upf/context/gnbcontext"
)

const moduleTag rlogger.ModuleTag = "n4context"

type N4SessionIDKey uint64

type KeyType uint8

const (
	//ImsiType      KeyType = 0
	//SessionIdType KeyType = 1

	// 3GPP TS 23.501 V15.3.0 (2018-09)
	// 5.8.2.11.2	N4 Session Context
	N4SessionIDCxtType KeyType = 2 //zj
)

// 3GPP TS 23.501 V15.3.0 (2018-09)
// 5.8.2.11.2	N4 Session Context
type N4SessionContext struct {
	SEID                     uint64
	SmfSEID                  pfcp.IEFSEID
	IMSI                     types3gpp.Imsi
	PDRs                     []*pfcp.IECreatePDR
	URRs                     []*pfcp.IECreateURR
	QERs                     []*pfcp.IECreateQER
	FARs                     []*pfcp.IECreateFAR
	BAR                      *pfcp.IECreateBAR
	CreateTrafficEndpoints   []*pfcp.IECreateTrafficEndpoint
	PDNType                  *pfcp.IEPDNType
	UserPlaneInactivityTimer *pfcp.IEUserPlaneInactivityTimer
	UserID                   *pfcp.IEUserID
	TraceInformation         *pfcp.IETraceInformation
	//	CN tunnel info.
	LocalFTEID map[uint16]*pfcp.IEFTEID
	//-	Network instance.
	NetworkInstance map[uint16]*pfcp.IENetworkInstance
	//-	QFIs.
	PDRQFIs map[uint16][]*pfcp.IEQFI
	//-	IP Packet Filter Set
	SDFFilters map[uint16][]*pfcp.IESDFFilter
	//Application Identifier
	ApplicationID map[uint16]*pfcp.IEApplicationID
	//Ethernet Packet Filter Set
	EthPacketFilters map[uint16][]*pfcp.IEEthernetPacketFilter

	// counter table
	MetricItems         metric.Registry // 16byte
	MetricItemsSnapshot metric.Registry

	// buffer
	Buffer      *list.List // []byte
	BufferState bool       // true:open,false:close
	//BufferFar pfcp.IECreateFAR
	Cause uint8

	// n4 node id
	PfcpNodeId string // pfcp 节点 IP
	GtpuNodeID string // gtpu 节点 IP

	GnbInfo *gnbcontext.GnbInfo //基站信息
	// test guangzhou
	GnbTeid types3gpp.Teid // gnb teid
	GnbIp   net.IP

	UeIp       net.IP             //UeIp
	NewGnbInfo gnbcontext.GnbInfo //新基站信息，用于N2切换
	NewGnbTeid types3gpp.Teid     //new gnb teid
	// todo 增加N4 smf侧gtp通道ip和端口
	N4SMFGTPIp net.IP         //SMF N4口
	N4SMFTeid  types3gpp.Teid //SMF N4口 teid
}

func (ctx *N4SessionContext) Copy() *N4SessionContext {
	if ctx == nil {
		return ctx
	}
	n4ctx := *ctx
	tools.Update(
		&(n4ctx.PDRs),
		&(n4ctx.URRs),
		&(n4ctx.QERs),
		&(n4ctx.FARs),
		&(n4ctx.BAR),
		&(n4ctx.CreateTrafficEndpoints),
		&(n4ctx.PDNType),
		&(n4ctx.UserPlaneInactivityTimer),
		&(n4ctx.UserID),
		&(n4ctx.TraceInformation),
	)
	return &n4ctx
}

/// types.IGetAMFTraceFunc
/*func (p *N4SessionContext) ConstructUPFTraceObj() interface{} {
	if p == nil {
		return nil
	}

	traceObj := rlogger.CreateUPFTraceValueCtxt()

	traceObj.UPFSEID = types.Uint64Valid{V: p.SEID, Valid: true}
	traceObj.SMFSEID = types.Uint64Valid{V: p.SEID.SEID, Valid: true}

	return traceObj
}
*/
func NewN4SessionContextForTest() *N4SessionContext {
	return &N4SessionContext{
		PDRs: []*pfcp.IECreatePDR{
			&pfcp.IECreatePDR{
				OuterHeaderRemoval: &pfcp.IEOuterHeaderRemoval{},
			},
			&pfcp.IECreatePDR{
				OuterHeaderRemoval: &pfcp.IEOuterHeaderRemoval{},
			},
		},
		URRs: []*pfcp.IECreateURR{
			&pfcp.IECreateURR{
				VolumeQuota: &pfcp.IEVolumeQuota{
					TotalVolume: 56,
				},
			},
			&pfcp.IECreateURR{
				VolumeQuota: &pfcp.IEVolumeQuota{
					TotalVolume: 56,
				},
			},
		},
	}
}
