package pdr

import (
	"lite5gc/cmn/nas/nasie"
	"lite5gc/cmn/rlogger"
	"net"
)

//3GPP TS 29.244 V15.5.0 (2019-03)
//5.2	Packet Forwarding Model

/*On receipt of a user plane packet, the UP function shall perform a lookup of the provisioned PDRs and:
 */

// lookup of the provisioned PDRs
// 下行接口
func LookupPDRs(
	tuple *IpPacketHeaderFields) (*PacketDetectionRule, error) {
	//rlogger.FuncEntry(moduleTag, nil) // moc 包过滤日志过多
	dstN4 := &ueIpN4SessionTable
	n4Pdr := &n4SessionPDRsTable
	if tuple == nil || dstN4 == nil {
		rlogger.Trace(moduleTag, rlogger.WARN, nil, "LookupPDRs Input parameter check failed")
		return nil, ErrNil
	}
	// 获取SEID
	ipRule, err := getSEID(tuple, dstN4)
	if err != nil {
		return nil, err
	}
	// 如果相同五元组已经查询过最佳匹配，则直接使用
	// todo：
	srcP := tuple
	if ipRule.Pdr != nil {
		dstP := &ipRule.Pdr.SrcField
		if ipRule.Pdr.Result {
			// 比较五元组
			if dstP.DstIp.Equal(srcP.DstIp) &&
				dstP.SrcIp.Equal(srcP.SrcIp) &&
				dstP.DstPort == srcP.DstPort &&
				dstP.SrcPort == srcP.SrcPort &&
				dstP.Protocol == srcP.Protocol {
				if rlogger.IsLevelDebug() {
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil,
						"Reusing: Input(SrcIp %s,SrcPort %d,DstIp %s,DstPort %d,Protocol %d),output(ue ip %s,seid %d),%s",
						dstP.SrcIp, dstP.SrcPort, dstP.DstIp, dstP.DstPort, dstP.Protocol, ipRule.UeIp, ipRule.SEID, ipRule.Pdr.Pdr)
				}
				return ipRule.Pdr.Pdr, nil
			}
		}
	}
	// 获取PDRs列表
	pdrs, err := getPDRs(ipRule.SEID, n4Pdr)
	if err != nil {
		return nil, err
	}
	// print Orderly PDRs
	if rlogger.IsLevelDebug() {
		OrderlyPDRsPrint(pdrs)
	}
	// 源匹配字段，从收到data中获取的五元组
	src := IpPacketSrcFields{}
	src.SrcIp = tuple.SrcIp
	src.SrcPort = tuple.SrcPort
	src.DstIp = tuple.DstIp
	src.DstPort = tuple.DstPort
	src.Protocol = tuple.Protocol
	src.Direction = tuple.Direction
	src.ToSTrafficClass = 0
	src.FlowLabel = 0
	src.SecurityParameterIndex = 0

	// 匹配PDR，返回匹配的PDR，从pdr列表中匹配一个
	pdr, err := getMatchingPDR(pdrs, src)
	if err != nil {
		return nil, err
	}
	// print match PDR
	if rlogger.IsLevelDebug() {
		MatchingDLPDRPrint(pdr, tuple, &ipRule)
	}
	// 记录已经匹配的规则
	ipRule.Pdr = pdr
	dstN4.Update(tuple.DstIp.String(), ipRule)
	return pdr.Pdr, nil
}

func LookupULRSRASEID(
	teid uint32) (*TEIdN4SessionValue, error) {
	//rlogger.FuncEntry(moduleTag, nil)
	dstN4 := &teidMatchingN4N4SessionTable
	if dstN4 == nil {
		rlogger.Trace(moduleTag, rlogger.WARN, nil, "Input parameter check failed")
		return nil, ErrNil //errors.New("Input parameter is nil")
	}
	// 获取SEID
	ipRule, err := getUlSEID(teid, dstN4)
	if err != nil {
		return nil, err
	}
	return &ipRule, err
}
func ChargingIsN9TEID(teid uint32) bool {
	rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "N9TEIDTable %v, teid %v", N9TEIDTable, teid)
	if N9TEIDTable == nil {
		return false
	}
	for _, v := range N9TEIDTable {
		if v != 0 && v == teid {
			rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "v %v, teid %v", v, teid)
			return true
		}
	}
	return false
}

// 上行接口
func LookupULPDRs(
	teid uint32, tuple *IpPacketHeaderFields) (*PacketDetectionRule, error) {
	//rlogger.FuncEntry(moduleTag, nil)
	dstN4 := &teidMatchingN4N4SessionTable
	n4Pdr := &n4SessionPDRsTable
	if tuple == nil || dstN4 == nil {
		rlogger.Trace(moduleTag, rlogger.WARN, nil, "Input parameter check failed")
		return nil, ErrNil //errors.New("Input parameter is nil")
	}
	// 获取SEID
	ipRule, err := getUlSEID(teid, dstN4)
	if err != nil {
		return nil, err
	}
	// 如果相同五元组已经查询过最佳匹配，则直接使用
	// todo：
	srcP := tuple
	if ipRule.Pdr != nil {
		dstP := &ipRule.Pdr.SrcField
		if ipRule.Pdr.Result {
			// 比较五元组
			if dstP.DstIp.Equal(srcP.DstIp) &&
				dstP.SrcIp.Equal(srcP.SrcIp) &&
				dstP.DstPort == srcP.DstPort &&
				dstP.SrcPort == srcP.SrcPort &&
				dstP.Protocol == srcP.Protocol {
				if rlogger.IsLevelDebug() {
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil,
						"Reusing: Input(SrcIp %s,SrcPort %d,DstIp %s,DstPort %d,Protocol %d),output(teid %d,seid %d),%s",
						dstP.SrcIp, dstP.SrcPort, dstP.DstIp, dstP.DstPort, dstP.Protocol, ipRule.TEID, ipRule.SEID, ipRule.Pdr.Pdr)
				}
				return ipRule.Pdr.Pdr, nil
			}
		}
	}
	// 获取PDRs列表
	pdrs, err := getPDRs(ipRule.SEID, n4Pdr)
	if err != nil {
		return nil, err
	}
	// print Orderly PDRs
	if rlogger.IsLevelDebug() {
		OrderlyPDRsPrint(pdrs)
	}
	// 源匹配字段，从收到data中获取的五元组
	src := IpPacketSrcFields{}
	src.SrcIp = tuple.SrcIp
	src.SrcPort = tuple.SrcPort
	src.DstIp = tuple.DstIp
	src.DstPort = tuple.DstPort
	src.Protocol = tuple.Protocol
	src.Direction = tuple.Direction
	src.ToSTrafficClass = 0
	src.FlowLabel = 0
	src.SecurityParameterIndex = 0

	// 匹配PDR，返回匹配的PDR，从pdr列表中匹配一个
	pdr, err := getMatchingPDR(pdrs, src)
	if err != nil {
		return nil, err
	}
	// print match PDR
	if rlogger.IsLevelDebug() {
		MatchingPDRPrint(pdr, tuple, &ipRule)
	}
	// 记录已经匹配的规则
	ipRule.Pdr = pdr
	dstN4.Update(teid, ipRule)
	return pdr.Pdr, nil
}

/*-	identify first the PFCP session to which the packet corresponds; and*/
func getSEID(tuple *IpPacketHeaderFields, dst *UEIpMatchingN4SessionTable) (UEIpN4SessionValue, error) {
	//rlogger.FuncEntry(moduleTag, nil)
	// N6 receipt
	if tuple.Direction == nasie.DownlinkOnly {
		if value, ok := dst.Get(tuple.DstIp.String()).(UEIpN4SessionValue); ok {
			rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Down link,get SEID:%v", value.SEID)
			return value, nil
		}
	}
	if tuple.Direction == nasie.UplinkOnly {
		if value, ok := dst.Get(tuple.SrcIp.String()).(UEIpN4SessionValue); ok {
			rlogger.Trace(moduleTag, rlogger.WARN, nil, "Up link,get SEID:%v", value.SEID)
			return value, nil
		}
	}
	err := ErrNoMatchSession //errors.New("No matching session")
	//rlogger.Trace(moduleTag, rlogger.ERROR, nil,  "No matching session")
	return UEIpN4SessionValue{}, err
}

// teid to seid
func getUlSEID(teid uint32, dst *TEIdMatchingN4N4SessionTable) (TEIdN4SessionValue, error) {
	FuncEntry(moduleTag, nil)
	// N3 receipt
	if value, ok := dst.Get(teid).(TEIdN4SessionValue); ok {
		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Up link,get SEID:%v", value.SEID)
		return value, nil
	}

	err := ErrNoMatchSession //errors.New("No matching session")
	rlogger.Trace(moduleTag, rlogger.WARN, nil, "No matching session")
	return TEIdN4SessionValue{}, err
}

func GetSeidByTeid(teid uint32) (uint64, error) {
	// N3 receipt
	dst := &teidMatchingN4N4SessionTable
	if value, ok := dst.Get(teid).(TEIdN4SessionValue); ok {
		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Up link,get SEID:%v", value.SEID)
		return value.SEID, nil
	}

	err := ErrNoMatchSession //errors.New("No matching session")
	rlogger.Trace(moduleTag, rlogger.WARN, nil, "No matching session")
	return TEIdN4SessionValue{}.SEID, err
}

/*
-	find the first PDR matching the incoming packet, among all the PDRs provisioned for this PFCP session,
starting with the PDRs with the highest precedence and continuing then with PDRs in decreasing order of precedence.
Only the highest precedence PDR matching the packet shall be selected,
i.e. the UP function shall stop the PDRs lookup once a matching PDR is found.
*/
func getPDRs(seid uint64, n4Pdr *N4SessionPDRsOrderlyTable) (*OrderlyFieldNumPDRs, error) {
	FuncEntry(moduleTag, nil)
	//为此pfcp会话提供的所有pdr
	if pdrs, ok := n4Pdr.Get(seid).(*OrderlyFieldNumPDRs); ok {
		return pdrs, nil
	}
	return nil, ErrNoMatchPdrs //errors.New("No matching pdrs")
}

/*A packet matches a PDR if all the match fields which are identified with different IE type
in the PDI of the PDR are matching the corresponding packet header fields.

If a match field is not included in the PDI, it shall be considered as matching
all possible values in the header field of the packet.

If the match field is present and does not include a mask,
the match field shall be considered as matching the corresponding header field of the packet if it has the same value.

If the match field is present and includes a mask
(e.g. IP address with a prefix mask), the match field shall be considered as
matching the corresponding header field of the packet if it has the same value
for the bits which are set in the mask.

If a match field has multiple instances, i.e. there are several IEs with the same IE type,
a packet matches this match field if any instance is matching the corresponding packet header field.
The match fields of the PDI shall correspond to outer and/or inner packet header fields,
e.g. uplink bearer binding verification in the PGW-U may be achieved by
configuring a PDR with the PDI containing the local GTP-U F-TEID (for outer IP packet matching)
and the SDF filters of the data flows mapped to the bearer (for inner IP packet matching).

The UP function should drop packets unmatched by any PDRs.*/

// 匹配PDR，返回匹配的PDR
func getMatchingPDR(pdr *OrderlyFieldNumPDRs, src IpPacketSrcFields) (*MatchPDR, error) {
	FuncEntry(moduleTag, nil)
	for e := pdr.pdrList.Front(); e != nil; e = e.Next() {
		//fmt.Println(e.Value)
		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Input IpPacketSrcFields Info: %+v", src)
		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "PDR orderly field Info: %+v", e.Value)
		// 目的规则
		dstRule := e.Value.(PDRFields)
		// 源规则
		srcRule := src
		fieldNum := NameIndex_max
		sameFlag := make([]bool, fieldNum)  //[fieldNum]bool{}  //重复出现标志
		matchFlag := make([]bool, fieldNum) //[fieldNum]bool{} //匹配标志
		// 从目的中匹配一个结果，目的字段出现才匹配
		for _, dstField := range dstRule.Fields {
			switch dstField.NameIndex {
			// 不同字段，有一个不匹配，则匹配不成功
			case NameIndex_SrcIP: //todo 需要考虑重复出现的情况
				// 相同字段，没有一个匹配则本字段匹配不成功
				// 已经匹配
				if matchFlag[NameIndex_SrcIP] == true {
					break
				}
				// 首次匹配成功
				// IP 精确匹配
				if m, ok := dstField.value.(net.IP); ok {
					if m.Equal(srcRule.SrcIp) {
						sameFlag[NameIndex_SrcIP] = true
						matchFlag[NameIndex_SrcIP] = true
						break
					}
				}

				//IP掩码匹配
				if m, ok := dstField.value.(CidrMatch); ok {
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "pdr src:%+v", m.cidr.IP)
					if m.match("", "", srcRule.SrcIp) || m.cidr.IP.Equal([]byte{0, 0, 0, 0}) {
						sameFlag[NameIndex_SrcIP] = true
						matchFlag[NameIndex_SrcIP] = true
						break
					}
				}

				//不匹配记录
				sameFlag[NameIndex_SrcIP] = true
				matchFlag[NameIndex_SrcIP] = false
			case NameIndex_SrcPort:
				if matchFlag[NameIndex_SrcPort] == true {
					break
				}
				// 首次匹配成功
				if (dstField.value.(PortRange)).MinPort <= srcRule.SrcPort &&
					srcRule.SrcPort <= (dstField.value.(PortRange)).MaxPort {
					sameFlag[NameIndex_SrcPort] = true
					matchFlag[NameIndex_SrcPort] = true
					break
				}
				//不匹配记录
				sameFlag[NameIndex_SrcPort] = true
				matchFlag[NameIndex_SrcPort] = false
			case NameIndex_DstIp:
				if matchFlag[NameIndex_DstIp] == true {
					break
				}
				// 首次匹配成功
				// IP 精确匹配
				if m, ok := dstField.value.(net.IP); ok {
					if m.Equal(srcRule.DstIp) {
						sameFlag[NameIndex_DstIp] = true
						matchFlag[NameIndex_DstIp] = true
						break
					}
				}
				//IP掩码匹配
				if m, ok := dstField.value.(CidrMatch); ok {
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "pdr dst:%+v", m.cidr.IP)
					if m.match("", "", srcRule.DstIp) || m.cidr.IP.Equal([]byte{0, 0, 0, 0}) {
						sameFlag[NameIndex_DstIp] = true
						matchFlag[NameIndex_DstIp] = true
						break
					}
				}
				//不匹配记录
				sameFlag[NameIndex_DstIp] = true
				matchFlag[NameIndex_DstIp] = false
			case NameIndex_DstPort:
				if matchFlag[NameIndex_DstPort] == true {
					break
				}
				// 首次匹配成功
				if (dstField.value.(PortRange)).MinPort <= srcRule.DstPort &&
					srcRule.DstPort <= (dstField.value.(PortRange)).MaxPort {
					sameFlag[NameIndex_DstPort] = true
					matchFlag[NameIndex_DstPort] = true
					break
				}
				//不匹配记录
				sameFlag[NameIndex_DstPort] = true
				matchFlag[NameIndex_DstPort] = false
			case NameIndex_Protocol:
				if matchFlag[NameIndex_Protocol] == true {
					break
				}
				// 首次匹配成功
				if byte(dstField.value.(IPProtocol)) == (srcRule.Protocol) {
					sameFlag[NameIndex_Protocol] = true
					matchFlag[NameIndex_Protocol] = true
					break
				}
				//不匹配记录
				sameFlag[NameIndex_Protocol] = true
				matchFlag[NameIndex_Protocol] = false
			case NameIndex_ToSTrafficClass:
				if matchFlag[NameIndex_ToSTrafficClass] == true {
					break
				}
				// 首次匹配成功
				if dstField.value.(uint16) == (srcRule.ToSTrafficClass) {
					sameFlag[NameIndex_ToSTrafficClass] = true
					matchFlag[NameIndex_ToSTrafficClass] = true
					break
				}
				//不匹配记录
				sameFlag[NameIndex_ToSTrafficClass] = true
				matchFlag[NameIndex_ToSTrafficClass] = false
			case NameIndex_FlowLabel:
				if matchFlag[NameIndex_FlowLabel] == true {
					break
				}
				// 首次匹配成功
				if dstField.value.(uint32) == (srcRule.FlowLabel) {
					sameFlag[NameIndex_FlowLabel] = true
					matchFlag[NameIndex_FlowLabel] = true
					break
				}
				//不匹配记录
				sameFlag[NameIndex_FlowLabel] = true
				matchFlag[NameIndex_FlowLabel] = false
			case NameIndex_SecurityParameterIndex:
				if matchFlag[NameIndex_SecurityParameterIndex] == true {
					break
				}
				// 首次匹配成功
				if dstField.value.(uint32) == (srcRule.SecurityParameterIndex) {
					sameFlag[NameIndex_SecurityParameterIndex] = true
					matchFlag[NameIndex_SecurityParameterIndex] = true
					break
				}
				//不匹配记录
				sameFlag[NameIndex_SecurityParameterIndex] = true
				matchFlag[NameIndex_SecurityParameterIndex] = false
			case NameIndex_Direction:
				if matchFlag[NameIndex_Direction] == true {
					break
				}
				// 首次匹配成功
				if dstField.value.(nasie.PacketFilterDirection) == (srcRule.Direction) {
					sameFlag[NameIndex_Direction] = true
					matchFlag[NameIndex_Direction] = true
					break
				}
				//不匹配记录
				sameFlag[NameIndex_Direction] = true
				matchFlag[NameIndex_Direction] = false
				/*default:
				dstRule.Result = true // 匹配*/
			}
		}
		//	汇总各字段匹配结果
		matchResult := MatchPDR{}
		matchResult.Result = true // 默认匹配
		// 当pdr没有SDF时或方向不一致时，直接跳过，不匹配该pdr
		if sameFlag[NameIndex_Direction] == false {
			continue
		}
		for i, value := range sameFlag {
			if value == true && matchFlag[i] == false {
				matchResult.Result = false
			}
		}
		//匹配情况检查，有一个匹配则成功返回
		if matchResult.Result == true {
			matchResult.Pdr = dstRule.Pdr
			matchResult.FieldSet = dstRule.Fields
			matchResult.SrcField = srcRule
			return &matchResult, nil
		}
	}
	return nil, ErrNoMatchPdr //errors.New("No matching pdr")
}
