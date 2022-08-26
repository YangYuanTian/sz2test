package pdr

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"github.com/intel-go/nff-go/packet"
	"lite5gc/cmn/message/pfcp"
	"lite5gc/cmn/message/pfcp/utils"
	"lite5gc/cmn/nas/nasie"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types/configure"
	"lite5gc/cmn/types3gpp"
	"lite5gc/cmn/userstrace"
	"lite5gc/oam/am"
	"lite5gc/upf/context/gnbcontext"
	"lite5gc/upf/context/n4context"
	"lite5gc/upf/service/gtpsignalling/signaldef"
	"lite5gc/upf/service/upfam"
	"net"
	"sort"
	"strconv"
)

// key:seid uint64,value:*OrderlyFieldNumPDRs
var n4SessionPDRsTable N4SessionPDRsOrderlyTable
var ueIpN4SessionTable UEIpMatchingN4SessionTable
var teidMatchingN4N4SessionTable TEIdMatchingN4N4SessionTable

// var n9TEID uint32
var N9TEIDTable []uint32

// dnn
var dnnGwIpTable DnnIPTable
var dnnGwIpv6Table DnnIPTable

func DnnTableReload(v4 map[string]string, v6 map[string]string) error {
	var v4table DnnIPTable
	var v6table DnnIPTable
	err := StoreDnnGwIpTable2(v4, &v4table, &v6table)
	if err != nil {
		return err
	}
	err = StoreDnnGwIpTable2(v6, &v4table, &v6table)
	if err != nil {
		return err
	}
	dnnGwIpTable = v4table
	dnnGwIpv6Table = v6table
	return nil
}

func DnnTablePrint() {
	rlogger.Trace(moduleTag, rlogger.ERROR, nil, "-----------------------------------------------")
	dnnGwIpTable.Range(func(key, value interface{}) bool {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "V4 dnn table key:%+v value:%+v\n", key, value)
		return true
	})
	dnnGwIpv6Table.Range(func(key, value interface{}) bool {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "V6 dnn table key:%+v value:%+v\n", key, value)
		return true
	})
	rlogger.Trace(moduleTag, rlogger.ERROR, nil, "-----------------------------------------------")
}

// UPF PDR 构造
// 3GPP TS 29.244 V15.5.0
// 5.2.1A	Packet Detection Rule Handling
var (
	ErrNil            = errors.New("Input parameter is nil")
	ErrNoMatchSession = errors.New("No matching session")
	ErrNoMatchPdrs    = errors.New("No matching pdrs")
	ErrNoMatchPdr     = errors.New("No matching pdr")
	ErrNoMatchDnn     = errors.New("No matching dnn")
)

// Create Packet Detection Rule tables
// 根据收到的PDRs构造UPF本地有序规则
func ConfigPDRsTable(n4Cxt *n4context.N4SessionContext) error { //Configuration rule tables
	rlogger.FuncEntry(moduleTag, n4Cxt)
	if n4Cxt == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Input parameter check failed")
		return errors.New("Input parameter is nil")
	}
	// 获取PDR并规整
	OrderlyPDRs, PDRs, err := ConfigPDRsRegular(n4Cxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Regular PDRs failed %s", err)
		return err
	}
	// 添加OrderlyFieldNumPDRs到N4SessionPDRsTable
	// key:seid uint64,value:*OrderlyFieldNumPDRs
	err = StoreConfigPDRsTable(n4Cxt, OrderlyPDRs, PDRs)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Store PDRs failed %s", err)
		return err
	}

	return nil
}

// 更新ConfigPDRsTable
func ConfigPDRsTableUpdate(n4Cxt *n4context.N4SessionContext) error { //Configuration rule tables
	rlogger.FuncEntry(moduleTag, n4Cxt)
	if n4Cxt == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Input parameter check failed")
		return errors.New("Input parameter is nil")
	}
	// 获取PDR并规整
	OrderlyPDRs, PDRs, err := ConfigPDRsRegular(n4Cxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Regular PDRs failed %s", err)
		return err
	}
	// 更新OrderlyFieldNumPDRs到N4SessionPDRsTable
	// key:seid uint64,value:*OrderlyFieldNumPDRs
	err = UpdateConfigPDRsTable(n4Cxt, OrderlyPDRs, PDRs)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Store PDRs failed %s", err)
		return err
	}

	return nil
}
func ConfigPDRsRegular(n4Cxt *n4context.N4SessionContext) (*OrderlyFieldNumPDRs, *PDRConfList, error) { //Configuration rule tables
	rlogger.FuncEntry(moduleTag, n4Cxt)
	if n4Cxt == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Input parameter check failed")
		return nil, nil, errors.New("Input parameter is nil")
	}
	// 获取PDRS
	var PDRs PDRConfList
	for _, pdr := range n4Cxt.PDRs {
		// Receiving PDR

		PDR, err := ReceivingPDRInfo(n4Cxt.SEID, pdr)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Receiving PDR Info failed %s", err)
			continue
		}
		if PDR.PDI.UEIPAddress != nil {
			n4Cxt.UeIp = PDR.PDI.UEIPAddress
		}
		// Receiving FAR
		FAR, err := ReceivingFARInfo(n4Cxt.FARs, PDR.FarI.FarID, n4Cxt)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Receiving FAR Info failed, %s", err)
			continue
		}
		PDR.FarI = FAR
		// Receiving QER
		QER, err := ReceivingQERInfo(n4Cxt.QERs, PDR.QerI, n4Cxt)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Receiving QER Info failed, %s", err)
			continue
		}
		PDR.QerI = QER
		// Receiving URR
		URR, err := ReceivingURRInfo(n4Cxt.URRs, PDR.UrrI, n4Cxt)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Receiving URR Info failed, %s", err)
			continue
		}
		PDR.UrrI = URR

		PDRs.PdrList = append(PDRs.PdrList, PDRListElement{Pdr: PDR})
		if PDR.PDI.UEIPAddress != nil && PDR.PDI.SourceInterface == nasie.DownlinkOnly { //pfcp.Core
			PDRs.UEIPAddress = PDR.PDI.UEIPAddress
			rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "PDRs.UEIPAddress %+v", PDRs.UEIPAddress)
		}
		if PDR.PDI.TEID != 0 && PDR.PDI.SourceInterface == nasie.DownlinkOnly { //pfcp.Core
			rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "PDRs.UpfTEID_N9 %+v", PDRs.UpfTEID_N9)
			PDRs.UpfTEID_N9 = PDR.PDI.TEID
		}
		//if PDR.PDI.UEIPAddress != nil && PDR.PDI.SourceInterface == nasie.UplinkOnly { //pfcp.Access
		if PDR.PDI.SourceInterface == nasie.UplinkOnly { //pfcp.Access
			PDRs.UpfTEID = PDR.PDI.TEID
		}
	}
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Received PDRs Info: %s", PDRs)
	// Regular PDR
	OrderlyPDRs, err := RegularPDR(PDRs)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Regular PDR failed %s", err)
		return nil, nil, err
	}
	// 添加OrderlyFieldNumPDRs到N4SessionPDRsTable
	// key:seid uint64,value:*OrderlyFieldNumPDRs
	//StoreConfigPDRsTable(n4Cxt, OrderlyPDRs, &PDRs)

	return OrderlyPDRs, &PDRs, nil
}

// 存储PDRs配置表
func StoreConfigPDRsTable(
	n4Cxt *n4context.N4SessionContext,
	OrderlyPDRs *OrderlyFieldNumPDRs,
	PDRs *PDRConfList) error { //Configuration rule tables
	rlogger.FuncEntry(moduleTag, n4Cxt)
	if n4Cxt == nil || OrderlyPDRs == nil || PDRs == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Input parameter check failed")
		return errors.New("Input parameter is nil")
	}
	// 添加OrderlyFieldNumPDRs到N4SessionPDRsTable
	// key:seid uint64,value:*OrderlyFieldNumPDRs
	err := n4SessionPDRsTable.Set(n4Cxt.SEID, OrderlyPDRs)
	if err != nil {
		if err.Error() == "key exist" {
			n4SessionPDRsTable.Update(n4Cxt.SEID, OrderlyPDRs)
			err = nil
		} else {
			err = fmt.Errorf("failed to set key(%d),err(%s)", n4Cxt.SEID, err)
			return err
		}
	}
	// UEIpN4SessionTable
	ueIPtoPDR := UEIpN4SessionValue{}
	ueIPtoPDR.SEID = n4Cxt.SEID
	ueIPtoPDR.UeIp = PDRs.UEIPAddress.String()
	ueIPtoPDR.Pdr = nil
	//抓包用的映射表 建立teid到seid的映射表，用户完成用户的数据包抓取
	if len(PDRs.UEIPAddress) != 0 {
		err := userstrace.AddUser(packet.SEID(n4Cxt.SEID), packet.UEIP(PDRs.UEIPAddress))
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt.SEID, "Store user id SEID:%v, ueip: %+v,failed", n4Cxt.SEID, PDRs.UEIPAddress)
		}
	}
	err = ueIpN4SessionTable.Set(ueIPtoPDR.UeIp, ueIPtoPDR)
	if err != nil {
		if err.Error() == "key exist" {
			ueIpN4SessionTable.Update(ueIPtoPDR.UeIp, ueIPtoPDR)
			err = nil
		} else {
			err = fmt.Errorf("failed to set key(%s),err(%s)", ueIPtoPDR.UeIp, err)
			return err
		}
	}

	//TEIdN4SessionTable
	teidN4SessionValue := TEIdN4SessionValue{}
	teidN4SessionValue.SEID = n4Cxt.SEID
	teidN4SessionValue.TEID = uint32(PDRs.UpfTEID) //todo:0值的处理
	teidN4SessionValue.Pdr = nil

	if teidN4SessionValue.TEID != 0 {
		err = teidMatchingN4N4SessionTable.Set(teidN4SessionValue.TEID, teidN4SessionValue)
		if err != nil {
			if err.Error() == "key exist" {
				teidMatchingN4N4SessionTable.Update(teidN4SessionValue.TEID, teidN4SessionValue)
				err = nil
			} else {
				err = fmt.Errorf("failed to set key(%d),err(%s)", teidN4SessionValue.TEID, err)
				return err
			}
		}
	}
	//n9TEID=uint32(PDRs.UpfTEID_N9)
	if PDRs.UpfTEID_N9 != 0 {
		N9TEIDTable = append(N9TEIDTable, uint32(PDRs.UpfTEID_N9))
		teidN4SessionValue1 := TEIdN4SessionValue{}
		teidN4SessionValue1.SEID = n4Cxt.SEID
		teidN4SessionValue1.TEID = uint32(PDRs.UpfTEID_N9) //todo:0值的处理
		teidN4SessionValue1.Pdr = nil
		if teidN4SessionValue1.TEID != 0 {
			err = teidMatchingN4N4SessionTable.Set(teidN4SessionValue1.TEID, teidN4SessionValue1)
			if err != nil {
				if err.Error() == "key exist" {
					teidMatchingN4N4SessionTable.Update(teidN4SessionValue1.TEID, teidN4SessionValue1)
					err = nil
				} else {
					err = fmt.Errorf("failed to set key(%d),err(%s)", teidN4SessionValue1.TEID, err)
					return err
				}
			}
		}
	}
	//抓包用的映射表 建立teid到seid的映射表，用户完成用户的数据包抓取
	//if PDRs.UpfTEID != 0 { //upf 本地的teid
	//	packet.ULTeidToSeid.Add(uint32(PDRs.UpfTEID), n4Cxt.SEID) //2
	//	//logcap.UserIdToSeid.Add(utils2.StrTransId(utils2.Teid(uint32(PDRs.UpfTEID))), n4Cxt.SEID)
	//	err := userstrace.SetUserID(PDRs.UpfTEID, n4Cxt.SEID)
	//	if err != nil {
	//		rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "set user id teid:%v to seid %+v failed", PDRs.UpfTEID, n4Cxt.SEID)
	//	}
	//}
	//err = teidMatchingN4N4SessionTable.Set(teidN4SessionValue.TEID, teidN4SessionValue)
	//if err != nil {
	//	if err.Error() == "key exist" {
	//		teidMatchingN4N4SessionTable.Update(teidN4SessionValue.TEID, teidN4SessionValue)
	//		err = nil
	//	} else {
	//		err = fmt.Errorf("failed to set key(%d),err(%s)", teidN4SessionValue.TEID, err)
	//		return err
	//	}
	//}

	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "StoreConfigure seid to n4 ,SEID:%v, pdrlist len: %+v", n4Cxt.SEID, OrderlyPDRs.pdrList.Len())
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "StoreConfigure ueip to pdr mapping Info: %+v", ueIPtoPDR)
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "StoreConfigure teid to pdr mapping Info: %+v", teidN4SessionValue)

	// print Orderly PDRs
	OrderlyPDRsPrint(OrderlyPDRs)
	return err
}

// 更新PDRs配置表
func UpdateConfigPDRsTable(
	n4Cxt *n4context.N4SessionContext,
	OrderlyPDRs *OrderlyFieldNumPDRs,
	PDRs *PDRConfList) error { //Configuration rule tables
	rlogger.FuncEntry(moduleTag, n4Cxt)
	if n4Cxt == nil || OrderlyPDRs == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Input parameter check failed")
		return errors.New("Input parameter is nil")
	}
	// 添加OrderlyFieldNumPDRs到N4SessionPDRsTable
	// key:seid uint64,value:*OrderlyFieldNumPDRs
	n4SessionPDRsTable.Update(n4Cxt.SEID, OrderlyPDRs)

	// UEIpN4SessionTable
	ueIPtoPDR := UEIpN4SessionValue{}
	ueIPtoPDR.SEID = n4Cxt.SEID
	ueIPtoPDR.UeIp = PDRs.UEIPAddress.String()
	ueIPtoPDR.Pdr = nil
	//抓包用的映射表 建立teid到seid的映射表，用户完成用户的数据包抓取
	if len(PDRs.UEIPAddress) != 0 {
		err := userstrace.AddUser(packet.SEID(n4Cxt.SEID), packet.UEIP(PDRs.UEIPAddress))
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt.SEID, "Store user id SEID:%v, ueip: %+v,failed", n4Cxt.SEID, PDRs.UEIPAddress)
		}
	}
	ueIpN4SessionTable.Update(ueIPtoPDR.UeIp, ueIPtoPDR)

	//TEIdN4SessionTable
	teidN4SessionValue := TEIdN4SessionValue{}
	teidN4SessionValue.SEID = n4Cxt.SEID
	teidN4SessionValue.TEID = uint32(PDRs.UpfTEID) //todo:0值的处理
	teidN4SessionValue.Pdr = nil
	teidMatchingN4N4SessionTable.Update(teidN4SessionValue.TEID, teidN4SessionValue)
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Update ueip to SEID mapping Info: %+v", ueIPtoPDR)
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Update teid to SEID mapping Info: %+v", teidN4SessionValue)
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Update SEID to PDRs mapping Info: %v,%+v", n4Cxt.SEID, OrderlyPDRs)
	// print Orderly PDRs
	OrderlyPDRsPrint(OrderlyPDRs)
	return nil
}

// 5.2.1A.2A	Provisioning of SDF filters
func ReceivingPDRInfo(seid uint64, pdr *pfcp.IECreatePDR) (*PacketDetectionRule, error) {
	//td := &rlogger.TraceV{types.UPFSEID_TRACE, seid}
	rlogger.FuncEntry(moduleTag, nil)
	if pdr == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Input parameter check failed")
		return nil, errors.New("Input parameter is nil")
	}
	var dstPdr PacketDetectionRule
	// M item
	//N4 Session ID
	dstPdr.SEID = seid
	//Rule ID
	dstPdr.RuleID = pdr.PDRID.RuleID
	//Precedence
	dstPdr.Precedence = pdr.Precedence.PrecedenceValue
	// PDI        PacketDetectionInfo
	//Source interface
	if pdr.PDI.SourceInterface.InterfaceValue == pfcp.Access {
		dstPdr.PDI.SourceInterface = nasie.UplinkOnly
	}
	if pdr.PDI.SourceInterface.InterfaceValue == pfcp.Core {
		dstPdr.PDI.SourceInterface = nasie.DownlinkOnly
	}

	// O item
	//UE IP address//IPv4
	if pdr.PDI.UEIPaddress != nil {
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "pdr.PDI.UEIPaddress : %+v", pdr.PDI.UEIPaddress)
		if pdr.PDI.UEIPaddress.IPv6Addr != nil {
			dstPdr.PDI.UEIPAddress = pdr.PDI.UEIPaddress.IPv6Addr
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "dstPdr.PDI.UEIPAddress : %+v", dstPdr.PDI.UEIPAddress)
		} else if pdr.PDI.UEIPaddress.IPv4Addr != nil {
			dstPdr.PDI.UEIPAddress = pdr.PDI.UEIPaddress.IPv4Addr
		}
	}
	//Network instance
	if pdr.PDI.NetworkInstance != nil {
		if pdr.PDI.NetworkInstance.NetworkInstance != "" {
			//apn 解码，格式：长度加字符
			tmpBytes := []byte(pdr.PDI.NetworkInstance.NetworkInstance)
			tmplen := byte(len(tmpBytes))
			tmpBytes = append([]byte{tmplen}, tmpBytes...)
			apn := types3gpp.Apn{}
			apnBuff := bytes.NewReader(tmpBytes)
			apn.Decode(apnBuff)
			dstPdr.PDI.NetworkInstance = apn.String()
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "PDI NetworkInstance dnn: %s", dstPdr.PDI.NetworkInstance)
		}
	}
	//CN tunnel info
	if pdr.PDI.LocalFTEID != nil {
		dstPdr.PDI.TEID = pdr.PDI.LocalFTEID.TEID
		dstPdr.PDI.UpfIpAddr = pdr.PDI.LocalFTEID.IPv4Addr
	}
	//Packet Filter Set
	if pdr.PDI.SDFFilters != nil {
		//dstPdr.PDI.PacketFilterSet.IpPacketFilterSet[0]. DstIp 可以与UEIP相同
		// 一个Session对应多个PDR，一个PDR对应多个过滤包过滤集，
		dstFilterSet := dstPdr.PDI.PacketFilterSet.IpPacketFilterSet
		for _, sdfFilter := range pdr.PDI.SDFFilters {
			if sdfFilter != nil {
				filter := IpPacketFilterSetTmp{}
				// 解析FlowDescription call FlowDescriptionParse
				FlowDescriptionParse(&filter, sdfFilter.FlowDescription)

				// 不使用sdf中的方向，使用PDI中的方向
				filter.Direction = dstPdr.PDI.SourceInterface
				//ts29.244 5.2.1A.2A	Provisioning of SDF filters
				//when the Source Interface is ACCESS, this indicates
				// that the filter is for uplink data flow, so the UP function
				// shall swap the source and destination address/port in the Flow Description;
				if filter.Direction == nasie.UplinkOnly {
					filter.SrcIp, filter.DstIp = filter.DstIp, filter.SrcIp
					filter.SrcPort, filter.DstPort = filter.DstPort, filter.SrcPort
				}

				filter.ToSTrafficClass = sdfFilter.ToSTrafficClass
				filter.FlowLabel = sdfFilter.FlowLabel
				filter.SecurityParameterIndex = sdfFilter.SecurityParameterIndex
				dstFilterSet = append(dstFilterSet, filter)
			}
		}
		dstPdr.PDI.PacketFilterSet.IpPacketFilterSet = dstFilterSet
		// Eth filter
		dstEthFilterSet := dstPdr.PDI.PacketFilterSet.EthPacketFilterSet
		for _, sdfFilter := range pdr.PDI.EthPacketFilters {
			if sdfFilter != nil {
				filter := EthPacketFilterSet{}
				// todo:需要解析FlowDescription call FlowDescriptionParse
				filter.SrcMac = sdfFilter.MACaddress.SrcMACValue[:]
				filter.DstMac = sdfFilter.MACaddress.DstMACValue[:]
				filter.EthType = sdfFilter.Ethertype.Ethertype
				filter.VID = int(sdfFilter.CTAG.CVIDValue)
				filter.PCP = sdfFilter.CTAG.PCPValue
				filter.DEI = sdfFilter.CTAG.DEIFlag

				dstEthFilterSet = append(dstEthFilterSet, filter)
			}
		}
		dstPdr.PDI.PacketFilterSet.EthPacketFilterSet = dstEthFilterSet
	}
	//Application ID
	if pdr.PDI.ApplicationID != nil {
		dstPdr.PDI.AppId = string(pdr.PDI.ApplicationID.ApplicationIdentifier)
	}
	//QoS Flow ID ,仅使用第一个QFI
	if pdr.PDI.QFIs != nil {
		for _, qfis := range pdr.PDI.QFIs {
			if qfis != nil {
				dstPdr.PDI.QFI = qfis.Value
				break
			}
		}
	}
	//Ethernet PDU Session Information
	if pdr.PDI.EthPDUSessionInfo != nil {
		dstPdr.PDI.ETHI = pdr.PDI.EthPDUSessionInfo.ETHI
	}

	// O item
	//Outer header removal
	if pdr.OuterHeaderRemoval != nil {
		dstPdr.OuterHeaderRemoval = pdr.OuterHeaderRemoval.Description
	}
	if pdr.PDI.SourceInterfaceType.InterfaceTypeValue == pfcp.N3_3GPP_Access {
		dstPdr.OuterHeaderRemoval = 0xff
	}
	if pdr.PDI.SourceInterface.InterfaceValue == pfcp.Core &&
		pdr.PDI.SourceInterfaceType.InterfaceTypeValue == pfcp.N9orN9fornon_roaming {
		dstPdr.OuterHeaderRemoval = 0xff
	}
	//Forwarding Action Rule ID
	if pdr.FARID != nil {
		dstPdr.FarI.FarID = pdr.FARID.Value
	}
	//List of Usage Reporting Rule ID(s)
	if pdr.URRIDs != nil {
		for i, uRRID := range pdr.URRIDs {
			if uRRID != nil {
				tmp := UrrInfo{}
				dstPdr.UrrI = append(dstPdr.UrrI, tmp)
				dstPdr.UrrI[i].UrrID = uRRID.URRIDValue
			}
		}
	}
	//List of QoS Enforcement Rule ID(s)
	if pdr.QERIDs != nil {
		for i, qERID := range pdr.QERIDs {
			if qERID != nil {
				tmp := QerInfo{}
				dstPdr.QerI = append(dstPdr.QerI, tmp)
				dstPdr.QerI[i].QerID = qERID.Value
			}
		}
	}

	rlogger.Trace(moduleTag, rlogger.INFO, nil, "Input SEID: %v,Output PacketDetectionRule: %s", seid, &dstPdr)
	//rlogger.Trace(moduleTag, rlogger.INFO, td,  "Output PacketDetectionRule: %+v", dstPdr)
	return &dstPdr, nil
}

// Receiving FAR
func ReceivingFARInfo(fars []*pfcp.IECreateFAR, farId uint32, n4Cxt *n4context.N4SessionContext) (FarInfo, error) {
	rlogger.FuncEntry(moduleTag, n4Cxt)
	//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Input FAR ID: %v", farId)
	for _, infar := range fars {
		if infar.FARID.Value == farId {
			rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Input FAR ID:%v,dnn input FAR info,ForwardingParameters: %+v", farId, infar.ForwardingParameters)
			farInfo := FarInfo{}
			farInfo.FarID = farId
			vFar := &ForwardActionRule{}
			vFar.RuleID = infar.FARID.Value
			vFar.Action = ActionT(infar.ApplyAction.Flag)

			if infar.ForwardingParameters != nil {
				rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Input FAR ID:%v,dnn input FAR info,NetworkInstance: %+v", farId, infar.ForwardingParameters.NetworkInstance)
				vFar.DstInterface = DestinationInterfaceT(infar.ForwardingParameters.DstInterface.Value)
				if infar.ForwardingParameters.NetworkInstance != nil {
					// apn 解码，格式：长度加字符
					tmpBytes := []byte(infar.ForwardingParameters.NetworkInstance.NetworkInstance)
					tmplen := byte(len(tmpBytes))
					tmpBytes = append([]byte{tmplen}, tmpBytes...)
					apn := types3gpp.Apn{}
					apnBuff := bytes.NewReader(tmpBytes)
					apn.Decode(apnBuff)
					vFar.NetworkInstance = apn.String()
					rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Input FAR ID:%v,dnn input FAR info,NetworkInstance dnn: %s", farId, infar.ForwardingParameters.NetworkInstance.NetworkInstance)
					rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "NetworkInstance dnn: %s", vFar.NetworkInstance)

					// 如果DNN本地没有配置，则返回错误指示
					DnIp := GetDnnGWIp(vFar.NetworkInstance)
					DnIpv6 := GetDnnGWIpv6(vFar.NetworkInstance)
					if DnIp == nil && DnIpv6 == nil {
						rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "DNN is not configured locally:%v", vFar.NetworkInstance)
						n4Cxt.Cause = pfcp.Cause_Mandatory_IE_incorrect
						//todo DNN 配置错误告警
						{
							ipString := ""
							if n4Cxt.SmfSEID.V4Flag == 1 {
								ipString = n4Cxt.SmfSEID.IPv4Addr.String()
							} else {
								ipString = n4Cxt.SmfSEID.IPv6Addr.String()
							}
							dnnSupport, _ := upfam.DNNSupport.Get(fmt.Sprintf("%d%s", n4Cxt.SmfSEID.SEID, ipString))
							if !dnnSupport {
								alarmDetails := upfam.UPFAlarmDetails{
									AlarmID:        am.UPFDNNError,
									Reason:         "DNN can't find out in local configure file",
									DNNRequestName: vFar.NetworkInstance,
									DNNLocal:       configure.UpfConf.DnnNameGwIpMap,
									Suggestion:     "check local dnn",
								}
								upfam.UPFAlarmReport(alarmDetails) //DNN 配置错误告警
								upfam.DNNSupport.Add(fmt.Sprintf("%d%s", n4Cxt.SmfSEID.SEID, ipString), true)
							}
						}

						return farInfo, ErrNoMatchDnn
					}
					////todo 如果这一次没有配置错误，同时上一次又配置错误的话，在此处产生告警清除
					//{
					//	ipString:=""
					//	if n4Cxt.SEID.V4Flag==1{
					//		ipString=n4Cxt.SEID.IPv4Addr.String()
					//	} else {
					//		ipString=n4Cxt.SEID.IPv6Addr.String()
					//	}
					//	if  upfam.DNNSupport[string(n4Cxt.SEID.SEID)+ipString] {
					//		alarmDetails:=upfam.UPFAlarmDetails{
					//			AlarmID: am.UPFDNNError,
					//			Reason:"DNN can't find out in local configure file",
					//			DNNRequestName:vFar.NetworkInstance,
					//			DNNLocal:configure.UpfConf.DnnNameGwIpMap,
					//		}
					//		upfam.UPFAlarmClear(alarmDetails)//DNN 配置错误 告警清除
					//		upfam.DNNSupport[string(n4Cxt.SEID.SEID)+ipString]=false
					//	}
					//}
					rlogger.Trace(moduleTag, rlogger.DEBUG, n4Cxt, "NetworkInstance dnn: %s,dst ip:%v,dst ipv6:%v", vFar.NetworkInstance, DnIp, DnIpv6)
				}

				vFar.OuterHeaderCreation = infar.ForwardingParameters.OuterHeaderCreation
				// 保存基站信息，为后续启动echo检测
				if vFar.OuterHeaderCreation != nil {
					// CPFunction记录SMF N4口GTP通道信息
					if vFar.DstInterface == DestinationInterface_CPFunction {
						var N4SMFGTPIp net.IP        //SMF N4口 ip/port
						var N4SMFTeid types3gpp.Teid //SMF N4口 teid
						if vFar.OuterHeaderCreation.Description == pfcp.IEOuterHCreation_GTPU_UDP_IPv4 {
							N4SMFGTPIp = vFar.OuterHeaderCreation.IPv4Addr
							N4SMFTeid = vFar.OuterHeaderCreation.TEID
							n4Cxt.N4SMFGTPIp = N4SMFGTPIp
							n4Cxt.N4SMFTeid = N4SMFTeid
						}
						if vFar.OuterHeaderCreation.Description == pfcp.IEOuterHCreation_GTPU_UDP_IPv6 {
							N4SMFGTPIp = vFar.OuterHeaderCreation.IPv6Addr
							N4SMFTeid = vFar.OuterHeaderCreation.TEID
							n4Cxt.N4SMFGTPIp = N4SMFGTPIp
							n4Cxt.N4SMFTeid = N4SMFTeid
						}
					} else if vFar.DstInterface != DestinationInterface_Core {
						var gnbInfo gnbcontext.GnbInfo
						if vFar.OuterHeaderCreation.Description == pfcp.IEOuterHCreation_GTPU_UDP_IPv4 {
							gnbInfo.IpType = gnbcontext.Type_IPv4_address
							gnbInfo.Ip.IP = vFar.OuterHeaderCreation.IPv4Addr
							gnbInfo.Teid = uint32(vFar.OuterHeaderCreation.TEID)
							n4Cxt.GnbInfo = &gnbInfo
							//test guangzhou
							n4Cxt.GnbIp = vFar.OuterHeaderCreation.IPv4Addr
							n4Cxt.GnbTeid = vFar.OuterHeaderCreation.TEID
						}
						if vFar.OuterHeaderCreation.Description == pfcp.IEOuterHCreation_GTPU_UDP_IPv6 {
							gnbInfo.IpType = gnbcontext.Type_IPv6_address
							gnbInfo.Ip.IP = vFar.OuterHeaderCreation.IPv6Addr
							n4Cxt.GnbInfo = &gnbInfo
							//test guangzhou
							n4Cxt.GnbIp = vFar.OuterHeaderCreation.IPv6Addr
							n4Cxt.GnbTeid = vFar.OuterHeaderCreation.TEID
						}
						n4Cxt.GnbInfo = &gnbInfo
						rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "OuterHeaderCreation n4Cxt.GnbIp: %+v", n4Cxt.GnbIp)
						rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "OuterHeaderCreation n4Cxt.GnbTeid: %+v", n4Cxt.GnbTeid)
						if len(gnbInfo.Ip.IP) != 0 {
							rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "OuterHeaderCreation GtpuNodeID: %s", n4Cxt.GtpuNodeID)
							if n4Cxt.GtpuNodeID == "" {
								// 新增 gnb info
								n4Cxt.GtpuNodeID = gnbInfo.Ip.IP.String()
							} else if n4Cxt.GtpuNodeID != gnbInfo.Ip.IP.String() {
								//	更新 gnb info，先删除
								gnbcontext.DeleteGnb(n4Cxt.GtpuNodeID)
								n4Cxt.GtpuNodeID = gnbInfo.Ip.IP.String()
								rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "OuterHeaderCreation gnb delete: %s", gnbInfo.Ip.IP)
							}

							// 重复不添加
							err := gnbcontext.AddGnb(gnbInfo.Ip.IP.String(), &gnbInfo)
							if err != nil {
								rlogger.Trace(moduleTag, rlogger.DEBUG, n4Cxt, "add gnb table: %s,dst ip:%v", err, gnbInfo.Ip)
							} else {
								// 新增gnb ，启动echo检测
								ok := signaldef.EchoServer.ReceiveMsg(&gnbInfo)
								if !ok {
									rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "echo server receive queue is full")
								}
							}
						}
						rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "OuterHeaderCreation gnb: %+v", gnbInfo)
					} else if vFar.DstInterface == DestinationInterface_Core {
						var gnbInfo gnbcontext.GnbInfo
						if vFar.OuterHeaderCreation.Description == pfcp.IEOuterHCreation_GTPU_UDP_IPv4 {
							gnbInfo.IpType = gnbcontext.Type_IPv4_address
							gnbInfo.Ip.IP = vFar.OuterHeaderCreation.IPv4Addr
							gnbInfo.Teid = uint32(vFar.OuterHeaderCreation.TEID)
						}
						if vFar.OuterHeaderCreation.Description == pfcp.IEOuterHCreation_GTPU_UDP_IPv6 {
							gnbInfo.IpType = gnbcontext.Type_IPv6_address
							gnbInfo.Ip.IP = vFar.OuterHeaderCreation.IPv6Addr
							gnbInfo.Teid = uint32(vFar.OuterHeaderCreation.TEID)
						}
						gnbcontext.PsaUpfTable.Set(gnbInfo.Ip.IP.String(), &gnbInfo)
					}
				}
				/**/
				vFar.SendEndMarker = 0
				if infar.ForwardingParameters.TransportLevelMarking != nil {
					vFar.ToSTrafficClass = infar.ForwardingParameters.TransportLevelMarking.ToSTrafficClass
				}
				if infar.ForwardingParameters.ForwardingPolicy != nil {
					vFar.ForwardingPolicy = infar.ForwardingParameters.ForwardingPolicy.Identifier
				}
				if infar.ForwardingParameters.Proxying != nil {
					if infar.ForwardingParameters.Proxying.ARP == true {
						vFar.Proxying = utils.BoolToUint8(infar.ForwardingParameters.Proxying.ARP) +
							(utils.BoolToUint8(infar.ForwardingParameters.Proxying.INS) << 1)
					}

				}

				vFar.HeaderEnrichment = infar.ForwardingParameters.HeaderEnrichment
			}

			vFar.BAR = n4Cxt.BAR

			farInfo.Far = vFar
			rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Input FAR ID:%v,Output FAR info: %+v", farId, farInfo.Far)
			return farInfo, nil
		}
	}
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "FAR(%v) did not find it.", farId)
	return FarInfo{}, nil
}

// Receiving QER
func ReceivingQERInfo(qers []*pfcp.IECreateQER, qerInfo []QerInfo, n4Cxt *n4context.N4SessionContext) ([]QerInfo, error) {
	rlogger.FuncEntry(moduleTag, n4Cxt)
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Input QER info: %+v", qerInfo)
	var result []QerInfo
	for _, dv := range qerInfo {
		for _, sv := range qers {
			if sv.QERID.Value == dv.QerID {
				qer := QerInfo{}
				qer.QerID = dv.QerID

				rule := QoSEnforcementRule{}
				rule.RuleID = dv.QerID
				rule.ULGateStatus = GateStatusT(sv.GateStatus.ULGate)
				rule.DLGateStatus = GateStatusT(sv.GateStatus.DLGate)
				rule.MBR = &sv.MaximumBitrate
				rule.GBR = &sv.GuaranteedBitrate
				rule.DLFlowLevelMarking.RQI = sv.ReflectiveQoS.RQI
				rule.QosFlowId.QFI = sv.QoSflowidentifier.Value
				qer.Qer = &rule
				rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Output QER info: %+v", rule)
				result = append(result, qer)
			}
		}
	}
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Output QER info: %+v", result)
	return result, nil
}

// Receiving URR
func ReceivingURRInfo(urrs []*pfcp.IECreateURR, urrInfo []UrrInfo, n4Cxt *n4context.N4SessionContext) ([]UrrInfo, error) {
	rlogger.FuncEntry(moduleTag, n4Cxt)
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Output URR info: %+v", urrInfo)
	var result []UrrInfo
	for _, dv := range urrInfo {
		for _, sv := range urrs {
			if sv.URRID.URRIDValue == dv.UrrID {
				urr := UrrInfo{}
				urr.UrrID = dv.UrrID
				//todo: 后续增加URR处理
				rule := sv
				urr.Urr = rule

				result = append(result, urr)
			}
		}
	}
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Output URR info: %+v", result)
	return result, nil
}

func DeleteMatchPDRsTable(n4Cxt *n4context.N4SessionContext) error {
	rlogger.FuncEntry(moduleTag, n4Cxt)
	pdrs := n4Cxt.PDRs
	for _, v := range pdrs {
		if v == nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, n4Cxt, "Current PDRs is nil.")
			return nil
		}
		if v.PDI.UEIPaddress != nil {
			// delete IptoPDRTable 中的记录
			ueIpN4SessionTable.Del(v.PDI.UEIPaddress.IPv4Addr.String())
			rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "delete success. IptoPDRTable.IP:%s", v.PDI.UEIPaddress.IPv4Addr.String())
		}
		if v.PDI.LocalFTEID != nil {
			// delete TeidtoPDRTable 中的记录
			teidMatchingN4N4SessionTable.Del(uint32(v.PDI.LocalFTEID.TEID))
			rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "delete success. TeidtoPDRTable.TEID:%v", v.PDI.LocalFTEID.TEID)
		}
		if v.PDI.SourceInterfaceType.InterfaceTypeValue == pfcp.N9orN9fornon_roaming &&
			v.PDI.SourceInterface.InterfaceValue == pfcp.Core &&
			v.PDI.LocalFTEID != nil {
			for i := 0; i < len(N9TEIDTable); i++ {
				if N9TEIDTable[i] == uint32(v.PDI.LocalFTEID.TEID) {
					N9TEIDTable = append(N9TEIDTable[:i], N9TEIDTable[i+1:]...)
				}
			}
		}
	}
	fars := n4Cxt.FARs
	for _, v := range fars {
		if v.ForwardingParameters != nil &&
			v.ForwardingParameters.DstInterface.Value == pfcp.IEDestinationInterface_Core &&
			v.ForwardingParameters.OuterHeaderCreation != nil {
			if v.ForwardingParameters.OuterHeaderCreation.IPv4Addr != nil {
				gnbcontext.PsaUpfTable.Del(v.ForwardingParameters.OuterHeaderCreation.IPv4Addr.String())
			}
			if v.ForwardingParameters.OuterHeaderCreation.IPv6Addr != nil {
				gnbcontext.PsaUpfTable.Del(v.ForwardingParameters.OuterHeaderCreation.IPv6Addr.String())
			}
		}
	}
	n4SessionPDRsTable.Del(n4Cxt.SEID)

	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "TeidtoPDRTable length:%d", teidMatchingN4N4SessionTable.Length())
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "IptoPDRTable length:%d", ueIpN4SessionTable.Length())
	rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "n4SessionPDRsTable length:%d", n4SessionPDRsTable.Length())

	return nil
}

// todo:需要解析FlowDescription，使用sourceinterf or 配置的Description确定？
// 5.2.1A.2A	Provisioning of SDF filters
func FlowDescriptionParse(filter *IpPacketFilterSetTmp, FlowDescription []byte) {
	rlogger.FuncEntry(moduleTag, nil)
	var dstRule IPFilterRule
	//dstRule.Decode(FlowDescription)// json parse
	dstRule.DecodeStd(FlowDescription) // standard parse
	_, ipnetA, _ := net.ParseCIDR(IpToIpMask(dstRule.SourceIP))
	//filter.SrcIp.IP = ip
	if ipnetA != nil {
		filter.SrcIp = *ipnetA
	}
	_, ipnetB, _ := net.ParseCIDR(IpToIpMask(dstRule.DestinationIP))
	if ipnetB != nil {
		filter.DstIp = *ipnetB
	}
	filter.SrcPort = ParsePortRange(dstRule.SourcePort)
	filter.DstPort = ParsePortRange(dstRule.DestinationPort)
	if dstRule.Protocol == "ip" {
		// 支持upd 17 、tcp 6 、icmp 1 协议,不过滤此字段，全匹配
		filter.Protocol = IPProtocolReserved
	} else {
		tmp, _ := strconv.Atoi(dstRule.Protocol)
		filter.Protocol = IPProtocol(tmp)
	}
	// Direction
	// RFC 6733
	// ir          "in" is from the terminal, "out" is to the
	//                      terminal.
	switch dstRule.Direction {
	case "out":
		filter.Direction = nasie.DownlinkOnly
	case "in":
		filter.Direction = nasie.UplinkOnly
	default:
		filter.Direction = nasie.Reserved
	}
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "Input  FlowDescription info: %s\n"+
		"Output ip filter info: %+v(Uplink Direction 2,Downlink Direction 1)", string(FlowDescription), *filter)
	//rlogger.Trace(moduleTag, rlogger.INFO, nil, "Output ip filter info: %+v", filter)
}

// Regular PDR
// 1、优先级；2、优先级相同时，字段数多在前
func RegularPDR(corePDRs PDRConfList) (*OrderlyFieldNumPDRs, error) {
	rlogger.FuncEntry(moduleTag, nil)
	//PDRs按照优先级排序
	// PDRs 构造，优先级有序，高到低
	sort.Sort(corePDRs)
	var precedencePDR OrderlyPrecedencePDR
	precedencePDR = OrderlyPrecedencePDR(corePDRs)
	// PDRs 构造，字段数有序，多到少。同等条件原则是匹配第一个，即成功匹配
	var PdrsFieldsList []PDRFields
	for _, pdr := range precedencePDR.PdrList {
		// PDR 映射到 MatchField
		fields := MappingPDRtoMatchField(pdr) //MatchFieldsList

		PdrsFieldsList = append(PdrsFieldsList, fields)
	}
	sort.Slice(PdrsFieldsList, func(i, j int) bool {
		// 1、优先级排序,升序
		if PdrsFieldsList[i].Precedence < PdrsFieldsList[j].Precedence {
			return true
		}
		// 2、字段数排序，降序
		if PdrsFieldsList[i].Precedence == PdrsFieldsList[j].Precedence {
			if PdrsFieldsList[i].Count > PdrsFieldsList[j].Count {
				return true
			}
		}
		return false
	})
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "Input PDRConfList info: %+v", corePDRs)
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "Output orderly PDRFields info: %+v", PdrsFieldsList)
	// 转换为list
	orderlyFieldNumPDRs := OrderlyFieldNumPDRs{}
	orderlyFieldNumPDRs.pdrList = list.New()
	for _, value := range PdrsFieldsList {
		orderlyFieldNumPDRs.pdrList.PushBack(value)
	}
	return &orderlyFieldNumPDRs, nil
}

// PDR 中 PacketFilterSet 映射到 MatchField
func MappingPDRtoMatchField(pdr PDRListElement) PDRFields {
	rlogger.FuncEntry(moduleTag, nil)
	fields := MatchFieldsList{}
	matchField := MatchField{}
	countField := [NameIndex_max]bool{} //重复出现标志
	//IpPacketDstFields todo：支持IP过滤类型

	IpPacketFilterSet := pdr.Pdr.PDI.PacketFilterSet.IpPacketFilterSet
	// 单个PDR中支持单个IpPacketFilterSet， 如果是多个时，作为重复字段添加  todo:可扩展只支持多个EthFilterSet
	for _, value := range IpPacketFilterSet {
		//SrcIp                  net.IP
		// mask 格式
		if value.SrcIp.Mask != nil {
			matchField.NameIndex = NameIndex_SrcIP
			matchField.value = CidrMatch{&value.SrcIp}
			fields = append(fields, matchField)
			countField[NameIndex_SrcIP] = true

		} else {
			if value.SrcIp.IP != nil {
				matchField.NameIndex = NameIndex_SrcIP
				matchField.value = value.SrcIp.IP
				fields = append(fields, matchField)

				countField[NameIndex_SrcIP] = true
			}
		}

		//SrcPort                int
		if value.SrcPort.MaxPort != 0 {
			matchField.NameIndex = NameIndex_SrcPort
			matchField.value = value.SrcPort
			fields = append(fields, matchField)
			countField[NameIndex_SrcPort] = true
		}
		//DstIp                  net.IP
		if value.DstIp.Mask != nil {
			matchField.NameIndex = NameIndex_DstIp
			matchField.value = CidrMatch{&value.DstIp}
			fields = append(fields, matchField)
			countField[NameIndex_DstIp] = true
		} else {
			if value.DstIp.IP != nil {
				matchField.NameIndex = NameIndex_DstIp
				matchField.value = value.DstIp.IP
				fields = append(fields, matchField)
				countField[NameIndex_DstIp] = true
			}
		}

		//DstPort                int
		if value.DstPort.MaxPort != 0 {
			matchField.NameIndex = NameIndex_DstPort
			matchField.value = value.DstPort
			fields = append(fields, matchField)
			countField[NameIndex_DstPort] = true
		}
		//Protocol               byte
		if value.Protocol != IPProtocolReserved {
			matchField.NameIndex = NameIndex_Protocol
			matchField.value = value.Protocol
			fields = append(fields, matchField)
			countField[NameIndex_Protocol] = true
		}
		//ToSTrafficClass        uint16 // ipv4 TOS //ipv6 Traffic class
		if value.ToSTrafficClass != 0 {
			matchField.NameIndex = NameIndex_ToSTrafficClass
			matchField.value = value.ToSTrafficClass
			fields = append(fields, matchField)
			countField[NameIndex_ToSTrafficClass] = true
		}
		//FlowLabel              uint32 // ipv6
		if value.FlowLabel != 0 {
			matchField.NameIndex = NameIndex_FlowLabel
			matchField.value = value.FlowLabel
			fields = append(fields, matchField)
			countField[NameIndex_FlowLabel] = true
		}
		//SecurityParameterIndex uint32 //types3gpp.SecurityIndication
		if value.SecurityParameterIndex != 0 {
			matchField.NameIndex = NameIndex_SecurityParameterIndex
			matchField.value = value.SecurityParameterIndex
			fields = append(fields, matchField)
			countField[NameIndex_SecurityParameterIndex] = true
		}
		//Direction              nasie.PacketFilterDirection
		if value.Direction != 0 {
			matchField.NameIndex = NameIndex_Direction
			matchField.value = value.Direction
			fields = append(fields, matchField)
			countField[NameIndex_Direction] = true
		}
	}
	pdrFields := PDRFields{}
	//if len(fields) == 0 {return nil} //todo: 为空时，当前是默认匹配规则
	pdrFields.Fields = fields //pdrFields
	pdrFields.Precedence = pdr.Pdr.Precedence
	pdrFields.Pdr = pdr.Pdr

	for i, _ := range countField {
		if countField[i] == true {
			pdrFields.Count += 1
		}
	}
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "Output Mapping MatchField info: %+v", pdrFields)
	return pdrFields
}

func GetDnnGWIp(dnn string) []byte {
	FuncEntry(moduleTag, nil)

	// dnn map to ip
	ip := dnnGwIpTable.Get(dnn)
	if ip == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to get key(%s)", dnn)
		return nil
	}
	if ipv4, ok := ip.([]byte); !ok {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to get value(%v)", ip)
		return nil
	} else {
		//rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Dnn:%s,IP:%v", dnn, ipv4)
		return ipv4
	}
}

func GetDnnGWIpv6(dnn string) []byte {
	FuncEntry(moduleTag, nil)

	// dnn map to ip
	ip := dnnGwIpv6Table.Get(dnn)
	if ip == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to get key(%s)", dnn)
		return nil
	}
	if ipv6, ok := ip.([]byte); !ok {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to get value(%v)", ip)
		return nil
	} else {
		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "Dnn:%s,IP:%v", dnn, ipv6)
		return ipv6
	}
}

func StoreDnnGwIpTable(ipmap map[string]string) error {
	for k, v := range ipmap {
		ip := []byte(net.ParseIP(v).To4())
		if ip == nil {
			ip = []byte(net.ParseIP(v).To16())
			err := dnnGwIpv6Table.Set(k, ip)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to set key(%s),err(%s)", k, err)
			}
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "success to set key(%s),ip(%v)", k, ip)
			continue
		}
		err := dnnGwIpTable.Set(k, ip)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to set key(%s),err(%s)", k, err)
		}
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "success to set key(%s),ip(%v)", k, ip)
	}
	return nil
}
func StoreDnnGwIpTable2(ipmap map[string]string, table *DnnIPTable, v6table *DnnIPTable) error {
	for k, v := range ipmap {
		ip := []byte(net.ParseIP(v).To4())
		if ip == nil {
			ip = []byte(net.ParseIP(v).To16())
			err := v6table.Set(k, ip)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to set key(%s),err(%s)", k, err)
			}
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "success to set key(%s),ip(%v)", k, ip)
			continue
		}
		err := table.Set(k, ip)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "failed to set key(%s),err(%s)", k, err)
		}
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "success to set key(%s),ip(%v)", k, ip)
	}
	return nil
}

func UpdateDnnGwIpTable(ipmap map[string]string) error {
	for k, v := range ipmap {
		ip := []byte(net.ParseIP(v).To4())
		dnnGwIpTable.Update(k, ip)
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "success to update key(%s),ip(%v)", k, ip)
	}
	return nil
}
