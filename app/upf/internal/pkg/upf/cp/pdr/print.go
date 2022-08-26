package pdr

import (
	"fmt"
	"lite5gc/cmn/nas/nasie"
	"lite5gc/cmn/rlogger"
)

func OrderlyPDRsPrint(pdrs *OrderlyFieldNumPDRs) {
	if pdrs == nil {
		return
	}
	l := pdrs.pdrList
	for e := l.Front(); e != nil; e = e.Next() {
		fields, _ := e.Value.(PDRFields)
		//fmt.Printf("PDR Fields:\n")
		//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "PDR Fields:\n")
		s := "PDR Fields:\n"
		for _, field := range fields.Fields {
			switch field.NameIndex {
			case NameIndex_SrcIP:
				if instance, ok := field.value.(CidrMatch); ok {
					//fmt.Printf("    SrcIP:%s\n", instance.cidr)
					//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "    SrcIP:%s", instance.cidr)
					s += fmt.Sprintf("    SrcIP:%s\n", instance.cidr)
				}
			case NameIndex_DstIp:
				if instance, ok := field.value.(CidrMatch); ok {
					//fmt.Printf("    DstIp:%s\n", instance.cidr)
					//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "    DstIp:%s", instance.cidr)
					s += fmt.Sprintf("    DstIp:%s\n", instance.cidr)
				}
			case NameIndex_SrcPort:
				if instance, ok := field.value.(PortRange); ok {
					//fmt.Printf("    SrcPort:%s\n", instance)
					//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "    SrcPort:%s", instance)
					s += fmt.Sprintf("    SrcPort:%s\n", instance)
				}
			case NameIndex_DstPort:
				if instance, ok := field.value.(PortRange); ok {
					//fmt.Printf("    DstPort:%s\n", instance)
					//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "    DstPort:%s", instance)
					s += fmt.Sprintf("    DstPort:%s\n", instance)
				}
			case NameIndex_Protocol:
				if instance, ok := field.value.(IPProtocol); ok {
					//fmt.Printf("    Protocol:%s\n", instance)
					//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "    Protocol:%s", instance)
					s += fmt.Sprintf("    Protocol:%s\n", instance)
				}
			case NameIndex_Direction:
				if instance, ok := field.value.(nasie.PacketFilterDirection); ok {
					dirStr := ""
					switch instance {
					case nasie.Reserved:
						dirStr = ""
					case nasie.DownlinkOnly:
						dirStr = "Down link"
					case nasie.UplinkOnly:
						dirStr = "Up link"
					case nasie.Bidirectional:
						dirStr = "Bidirectional"
					}
					//fmt.Printf("    Direction:%s\n", dirStr)
					//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "    Direction:%s", dirStr)
					s += fmt.Sprintf("    Direction:%s", dirStr)
					/*noteStr := `IPProtocolReserved       = 0
					                 DownlinkOnly   = 1
					                 UplinkOnly     = 2
									Bidirectional  = 3`
									fmt.Printf("%s",noteStr)*/
				}
			}
		}
		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "PDR Fields:%s", s)

	}
}

func MatchingDLPDRPrint(pdr *MatchPDR, Tuple *IpPacketHeaderFields, ueip *UEIpN4SessionValue) {

	if pdr == nil || Tuple == nil || ueip == nil {
		return
	}
	s := fmt.Sprintf("%+v,", *Tuple)
	s += fmt.Sprintf("ue ip %s,seid %d,", ueip.UeIp, ueip.SEID)
	s += fmt.Sprintf("PDR %s,", pdr.Pdr)
	rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "DL Matching PDR:%s", s)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil,  "    MatchResult:%t", pdr.Result)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil,  "    %+v", pdr.FieldSet)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil,  "    %+v", pdr.SrcField)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "    PDR:%s", pdr.Pdr)
}

func MatchingPDRPrint(pdr *MatchPDR, Tuple *IpPacketHeaderFields, teid *TEIdN4SessionValue) {

	if pdr == nil || Tuple == nil || teid == nil {
		return
	}
	s := fmt.Sprintf("%+v,", *Tuple)
	s += fmt.Sprintf("teid %d,seid %d,", teid.TEID, teid.SEID)
	s += fmt.Sprintf("PDR %s,", pdr.Pdr)
	rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "UL Matching PDR:%s", s)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "Matching PDR:")
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "    MatchResult:%t", pdr.Result)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "    %+v", pdr.FieldSet)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "    %+v", pdr.SrcField)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "    PDR:%s", pdr.Pdr)
}
