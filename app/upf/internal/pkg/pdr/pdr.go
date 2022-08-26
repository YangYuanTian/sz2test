package pdr

import (
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/util/gutil"
	"upf/internal/pkg/cmn/nas/nasie"
	"upf/internal/pkg/pktinfo"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/upf/cp/pdr"
)

type UlRuleGetter interface {
	GetUlRule(pkt *pktinfo.UlPkt) *rule.ULRule
}

type DlRuleGetter interface {
	GetDlRule(pkt *pktinfo.DlPkt) *rule.DLRule
}

type Adapter struct {
}

func (a Adapter) GetDlRule(pkt *pktinfo.DlPkt) (*rule.DLRule, error) {

	ft := pdr.IpPacketHeaderFields{
		SrcIp:     pkt.SrcIp,
		SrcPort:   pkt.SrcPort,
		DstIp:     pkt.DstIp,
		DstPort:   pkt.DstPort,
		Protocol:  pkt.Protocol,
		Direction: nasie.UplinkOnly,
		Length:    pkt.Length,
	}

	r, err := pdr.LookupPDRs(&ft)

	if err != nil {
		return nil, err
	}

	gutil.Dump(r)

	return nil, gerror.New("not implement")
}

func (a Adapter) GetUlRule(pkt *pktinfo.UlPkt) (*rule.DLRule, error) {

	ft := pdr.IpPacketHeaderFields{
		SrcIp:     pkt.SrcIp,
		SrcPort:   pkt.SrcPort,
		DstIp:     pkt.DstIp,
		DstPort:   pkt.DstPort,
		Protocol:  pkt.Protocol,
		Direction: nasie.UplinkOnly,
		Length:    pkt.Length,
	}

	r, err := pdr.LookupULPDRs(pkt.TEID, &ft)

	if err != nil {
		return nil, err
	}

	gutil.Dump(r)

	return nil, gerror.New("not implement")
}
