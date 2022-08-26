package rpc

import (
	"errors"
	"fmt"
	"lite5gc/cmn/message/pfcp"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types3gpp"
	"lite5gc/cmn/utils"
	"lite5gc/upf/context/n4context"
	. "lite5gc/upf/context/pdrcontext"
	"net"
)

//Create Packet Detection Rule tables

// Todo:存储并应用请求中收到的规则
func ConfigPDRsTable(n4Cxt *n4context.N4SessionContext) error { //Configuration rule tables
	rlogger.FuncEntry(moduleTag, utils.Seid(n4Cxt.SEID))
	// 获取PDRS
	var corePDRs CorePDRs
	var accessPDRs AccessPDRs
	for _, pdr := range n4Cxt.PDRs {
		sourceInterface := pdr.PDI.SourceInterface.InterfaceValue
		//sourceInterface := n4Cxt.PDRs[0].PDI.SourceInterface.InterfaceValue
		// 分上下行规则分别各创建一个map
		switch sourceInterface {
		case pfcp.Core:
			// 存储N6侧的过滤规则
			var corePDR CorePDR
			corePDR.SEID = n4Cxt.SEID
			corePDR.QFI = pdr.PDI.QFIs[0].Value // 5GS 当前使用一个QFI
			corePDR.UpfTEID = pdr.PDI.LocalFTEID.TEID
			corePDR.UpfIpAddress = pdr.PDI.LocalFTEID.IPv4Addr // 支持ipv4
			fmt.Println("ConfigPDRsTable pdr.PDI:", pdr.PDI)
			fmt.Println("ConfigPDRsTable pdr.LocalFTEID:", pdr.PDI.LocalFTEID)

			// 从FAR中设置 todo:在SessionModifyRequest消息中设置
			/*for _, v := range n4Cxt.FARs {
				if v.FARID.Value == pdr.FARID.Value {
					corePDR.GnbTEID = v.ForwardingParameters.OuterHeaderCreation.TEID
					corePDR.GnbIpAddress = v.ForwardingParameters.OuterHeaderCreation.IPv4Addr
				}
			}*/
			corePDR.PDR = pdr
			// UEIP
			if pdr.PDI.UEIPaddress != nil {
				corePDR.UEIPAddress = pdr.PDI.UEIPaddress.IPv4Addr
			}

			corePDRs.CorePdrs = append(corePDRs.CorePdrs, corePDR)

			err := CorePDRsSort(corePDRs)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "Failure of PDR acquisition for UE IP matching.")
			}

			iptoPdr := GetUEIPCanMatchPDR(corePDRs)
			if iptoPdr == nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "Failure of PDR acquisition for UE IP matching.")
				continue
			}
			err = SetCorePDRTable(iptoPdr)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "PDR table SET failed. err:%s", err)
			}
			rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(n4Cxt.SEID), "Core PDR table SET is %+v.", iptoPdr)
		case pfcp.Access:
			// 存储N3侧收到消息的过滤规则
			var accessPDR AccessPDR
			accessPDR.SEID = n4Cxt.SEID
			accessPDR.QFI = pdr.PDI.QFIs[0].Value // 5GS 当前使用一个QFI
			accessPDR.UpfTEID = pdr.PDI.LocalFTEID.TEID
			accessPDR.UpfIpAddress = pdr.PDI.LocalFTEID.IPv4Addr
			accessPDR.PDR = pdr
			//accessPDR.UEIPAddress=pdr.PDI.UEIPaddress.IPv4Addr

			accessPDRs.AccessPdrs = append(accessPDRs.AccessPdrs, accessPDR)
			// 按优先级排序
			err := AccessPDRsSort(accessPDRs)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "Failure of PDR acquisition for TEID matching.")
			}
			// 获取TEID匹配的PDR
			teidtoPdr := GetPDRmatchingTEID(accessPDRs)
			//fmt.Println("teidtoPdr: ", teidtoPdr)
			if teidtoPdr == nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "Failure of PDR acquisition for TEID matching.")
				continue
			}

			err = SetAccessPDRTable(teidtoPdr)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "PDR table SET failed. err:%s", err)
			}
			rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(n4Cxt.SEID), "Access PDR table SET is %+v.", teidtoPdr)

		case pfcp.SGi_LAN_or_N6_LAN:
			rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "Source Interface type(%d) unsupported.", sourceInterface)
		case pfcp.CP_function:
			rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "Source Interface type(%d) unsupported.", sourceInterface)
		}
	}
	return nil
}

// Core侧下行消息规则
func IpMatchPDR(ip net.IP) (*CorePDR, error) {
	if pdr, ok := IptoPDRTable.Get(ip.String()).(*CorePDR); ok {
		return pdr, nil
	}

	return nil, errors.New("false")
}

// Access侧上行消息规则
func TeidMatchPDR(teid types3gpp.Teid) (*AccessPDR, error) {
	if pdr, ok := TeidtoPDRTable.Get(uint32(teid)).(*AccessPDR); ok {
		return pdr, nil
	}

	return nil, errors.New("false")
}

func DeleteMatchPDRsTable(n4Cxt *n4context.N4SessionContext) error {
	rlogger.FuncEntry(moduleTag, utils.Seid(n4Cxt.SEID))
	pdrs := n4Cxt.PDRs
	for _, v := range pdrs {
		if v == nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID), "Current PDRs is nil.")
			return nil
		}
		if v.PDI.UEIPaddress != nil {
			// delete IptoPDRTable 中的记录
			IptoPDRTable.Del(v.PDI.UEIPaddress.IPv4Addr.String())
			rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(n4Cxt.SEID), "delete success. IptoPDRTable.IP:%s", v.PDI.UEIPaddress.IPv4Addr.String())
		}
		if v.PDI.LocalFTEID != nil {
			// delete TeidtoPDRTable 中的记录
			TeidtoPDRTable.Del(uint32(v.PDI.LocalFTEID.TEID))
			rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(n4Cxt.SEID), "delete success. TeidtoPDRTable.TEID:%v", v.PDI.LocalFTEID.TEID)
		}

	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(n4Cxt.SEID), "TeidtoPDRTable length:%d", TeidtoPDRTable.Length())
	rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(n4Cxt.SEID), "IptoPDRTable length:%d", IptoPDRTable.Length())

	return nil
}
