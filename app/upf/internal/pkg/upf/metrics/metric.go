package metrics

import (
	"bytes"
	"fmt"
	"time"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/metric"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types/configure"
	"upf/internal/pkg/cmn/types3gpp"
	"upf/internal/pkg/upf/context/n4context"
	"upf/internal/pkg/upf/cp/pdr"
)

const TickDuration = 5

// open counter
var SessionCounterStart = false
var ModuleCounterStart = true

// upf session 统计使用get获取指标变量
// 每个session 一个统计表MetricItems
func SessionCounterInit() (metric.Registry, error) {
	MetricItems := metric.NewMetricsMap()
	metric.CreateCounters(UpfSessionMetricsCounter, MetricItems)
	metric.MetersCreate(UpfSessionMetricsMeter, MetricItems)

	return MetricItems, nil
}

// notes:Meter required release
func SessionMeterRelease(r metric.Registry) error {
	metric.MetersRelease(UpfSessionMetricsMeter, r)

	return nil
}

// upf session pps 计算
// UpfCounterInit 中启动 upf session pps 计算
func upfSessionPps() {
	tickChan := time.Tick(TickDuration * time.Second)
	for {
		select {
		case <-tickChan:
			// 遍历N4上下文，对每个session 计算 pps
			n4List, err := n4context.ValuesOfN4ContextTbl(n4context.N4SessionIDCxtType)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to get N4 Context:%s", err)
				return
			}
			for _, v := range n4List {
				// 在每个MetricItems中计算pps
				CalcPPS(v.MetricItems, v.MetricItemsSnapshot)
			}
		}
	}
}

// 查询时计算pps
func upfSessionPpsOne(seid uint64) metric.Registry {

	// 遍历N4上下文，对每个session 计算 pps
	n4Cxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(seid))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to get N4 Context:%s", err)
		return nil
	}
	CalcPPS(n4Cxt.MetricItems, n4Cxt.MetricItemsSnapshot)
	tickChan := time.Tick(TickDuration * time.Second)
	for i := 0; i < 5; i++ {
		select {
		case <-tickChan:
			CalcPPS(n4Cxt.MetricItems, n4Cxt.MetricItemsSnapshot)
		}
	}

	return n4Cxt.MetricItems
}

// 计算PPS 保存到MetricItems
func CalcPPS(MetricItems metric.Registry, Snapshot metric.Registry) {
	// 计算区间值P-I
	//  事件数Mark:当前计数 - 前一次计数
	//  session
	//  UpLinkSessionPacketsSentPerSec,
	IntervalIncrementPPS(UpLinkSessionSendPacket, UpLinkSessionPacketsSentPerSec, MetricItems, Snapshot)
	// UpLinkSessionPacketsReceivedPerSec
	IntervalIncrementPPS(UpLinkSessionReceivedPacket, UpLinkSessionPacketsReceivedPerSec, MetricItems, Snapshot)
	//	DownLinkSessionPacketsSentPerSec,
	IntervalIncrementPPS(DownLinkSessionSendPacket, DownLinkSessionPacketsSentPerSec, MetricItems, Snapshot)
	//	DownLinkSessionPacketsReceivedPerSec,
	IntervalIncrementPPS(DownLinkSessionReceivedPacket, DownLinkSessionPacketsReceivedPerSec, MetricItems, Snapshot)
	//	UpLinkSessionBitsReceivedPerSec,
	IntervalIncrementPPS(UpLinkSessionBitsReceived, UpLinkSessionBitsReceivedPerSec, MetricItems, Snapshot)
	//	UpLinkSessionBitsSentPerSec,
	IntervalIncrementPPS(UpLinkSessionBitsSent, UpLinkSessionBitsSentPerSec, MetricItems, Snapshot)
	//	DownLinkSessionBitsReceivedPerSec,
	IntervalIncrementPPS(DownLinkSessionBitsReceived, DownLinkSessionBitsReceivedPerSec, MetricItems, Snapshot)
	//	DownLinkSessionBitsSentPerSec,
	IntervalIncrementPPS(DownLinkSessionBitsSent, DownLinkSessionBitsSentPerSec, MetricItems, Snapshot)
	//  PFCP
}

// Calculated interval increment
func IntervalIncrementPPS(srcname string, dstname string,
	MetricItems metric.Registry, Snapshot metric.Registry) int64 {
	srcMetric := metric.Get(srcname, MetricItems)
	snapshotMetric := metric.Get(srcname, Snapshot)
	if srcMetric == nil || snapshotMetric == nil {
		return 0
	}
	current := srcMetric.Count()
	PacketPI := current - snapshotMetric.Count()

	dstMetric := metric.GetMeter(dstname, MetricItems)
	if dstMetric == nil {
		return 0
	}
	dstMetric.Mark(PacketPI)

	Previous := metric.Get(srcname, Snapshot)
	if Previous != nil {
		Previous.Clear()
		Previous.Inc(current)
	}

	return PacketPI
}

// session info
func UpfSessionInfoGet(seid uint64) *UpfSessionInfo {
	info := &UpfSessionInfo{}
	n4Cxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(seid))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to get N4 Context:%s", err)
		return nil
	}
	info.UpfSessionID = n4Cxt.SEID

	// down link is pfcp.Core
	// todo 上下行只是读取一个PDR
	var farId uint32
	for _, pdrinfo := range n4Cxt.PDRs {
		if pdrinfo != nil {
			if pdrinfo.PDI.SourceInterface.InterfaceValue == pfcp.Core {
				info.DownLinkSessionRuleID, _ = pdrinfo.PDRID.Get()
				if pdrinfo.PDI.UEIPaddress != nil {
					info.DownLinkSessionUEIPAddress = pdrinfo.PDI.UEIPaddress.IPv4Addr.To4()
				}
				if pdrinfo.PDI.QFIs != nil && pdrinfo.PDI.QFIs[0] != nil {
					info.DownLinkSessionQoSFlowID, _ = pdrinfo.PDI.QFIs[0].Get()
				}
				if pdrinfo.PDI.SDFFilters != nil && pdrinfo.PDI.SDFFilters[0] != nil {
					info.DownLinkSessionFlowDescription = string(pdrinfo.PDI.SDFFilters[0].FlowDescription)
				}
				farId, _ = pdrinfo.FARID.Get()

				for _, far := range n4Cxt.FARs {
					if far.FARID.Value == farId {
						info.DownLinkSessionForwardingAction = far.ApplyAction.Flag
						if far.ForwardingParameters != nil && far.ForwardingParameters.OuterHeaderCreation != nil {
							info.DownLinkSessionOuterHeaderCreationTEID =
								fmt.Sprintf("0x%x(%d)", (far.ForwardingParameters.OuterHeaderCreation.TEID),
									(far.ForwardingParameters.OuterHeaderCreation.TEID))
							info.DownLinkSessionOuterHeaderCreationIPv4Address = far.ForwardingParameters.OuterHeaderCreation.IPv4Addr
						}
					}
				}
			}
			if pdrinfo.PDI.SourceInterface.InterfaceValue == pfcp.Access {
				info.UpLinkSessionRuleID, _ = pdrinfo.PDRID.Get()
				if pdrinfo.PDI.LocalFTEID != nil {
					info.UpLinkSessionTrafficEndpointID =
						fmt.Sprintf("0x%x(%d)", (pdrinfo.PDI.LocalFTEID.TEID),
							(pdrinfo.PDI.LocalFTEID.TEID))
				}
				if pdrinfo.PDI.QFIs != nil && pdrinfo.PDI.QFIs[0] != nil {
					info.UpLinkSessionQoSFlowID, _ = pdrinfo.PDI.QFIs[0].Get()
				}
				if pdrinfo.PDI.SDFFilters != nil && pdrinfo.PDI.SDFFilters[0] != nil {
					info.UpLinkSessionFlowDescription = string(pdrinfo.PDI.SDFFilters[0].FlowDescription)
				}
				if pdrinfo.OuterHeaderRemoval != nil {
					info.UpLinkSessionOuterHeaderRemovalDescription = pdrinfo.OuterHeaderRemoval.Description
				}
				farId, _ = pdrinfo.FARID.Get()

				for _, far := range n4Cxt.FARs {
					if far.FARID.Value == farId {
						info.UpLinkSessionForwardingAction = far.ApplyAction.Flag
						if far.ForwardingParameters != nil && far.ForwardingParameters.NetworkInstance != nil {
							//apn 解码，格式：长度加字符
							tmpBytes := []byte(far.ForwardingParameters.NetworkInstance.NetworkInstance)
							tmplen := byte(len(tmpBytes))
							tmpBytes = append([]byte{tmplen}, tmpBytes...)
							apn := types3gpp.Apn{}
							apnBuff := bytes.NewReader(tmpBytes)
							apn.Decode(apnBuff)
							info.UpLinkSessionNetworkInstance = apn.String()
						}
						info.UpLinkSessionDNGatewayIPAddress = pdr.GetDnnGWIp(info.UpLinkSessionNetworkInstance)
					}
				}
			}
		}

	}

	return info
}

// upf module 统计使用全局指标变量
var UpfmoduleSet UpfModule
var UpfmodulePISet UpfModulePI

func UpfCounterInit() (metric.Registry, error) {
	// switch
	SessionCounterStart = configure.UpfConf.Pm.Startsessioncount
	ModuleCounterStart = configure.UpfConf.Pm.Startmodulecount

	MetricItems := metric.NewMetricsMap()
	// forward
	UpfmoduleSet.TotalPackets = metric.NewCounter(totalPackets, MetricItems)
	UpfmoduleSet.TotalBits = metric.NewCounter(totalBits, MetricItems)
	UpfmoduleSet.TotalDiscardedPackets = metric.NewCounter(totalDiscardedPackets, MetricItems)

	// up link
	UpfmoduleSet.UpLinkTotalPacketsReceived = metric.NewCounter(upLinkTotalPacketsReceived, MetricItems)
	UpfmoduleSet.UpLinkTotalPacketsSent = metric.NewCounter(upLinkTotalPacketsSent, MetricItems)
	UpfmoduleSet.UpLinkTotalBitsSent = metric.NewCounter(upLinkTotalBitsSent, MetricItems)
	UpfmoduleSet.UpLinkTotalBitsReceived = metric.NewCounter(upLinkTotalBitsReceived, MetricItems)
	UpfmoduleSet.UpLinkTotalReceivedPacketsDiscarded = metric.NewCounter(upLinkTotalReceivedPacketsDiscarded, MetricItems)
	UpfmoduleSet.UpLinkTotalSentPacketsDiscarded = metric.NewCounter(upLinkTotalSentPacketsDiscarded, MetricItems)
	UpfmoduleSet.UpLinkTotalInvalidPackets = metric.NewCounter(upLinkTotalInvalidPackets, MetricItems)
	UpfmoduleSet.UpLinkTotalDiscardedPackets = metric.NewCounter(upLinkTotalDiscardedPackets, MetricItems)

	// down link
	UpfmoduleSet.DownLinkTotalPacketsReceived = metric.NewCounter(downLinkTotalPacketsReceived, MetricItems)
	UpfmoduleSet.DownLinkTotalPacketsSent = metric.NewCounter(downLinkTotalPacketsSent, MetricItems)
	UpfmoduleSet.DownLinkTotalBitsSent = metric.NewCounter(downLinkTotalBitsSent, MetricItems)
	UpfmoduleSet.DownLinkTotalBitsReceived = metric.NewCounter(downLinkTotalBitsReceived, MetricItems)
	UpfmoduleSet.DownLinkTotalReceivedPacketsDiscarded = metric.NewCounter(downLinkTotalReceivedPacketsDiscarded, MetricItems)
	UpfmoduleSet.DownLinkTotalSentPacketsDiscarded = metric.NewCounter(downLinkTotalSentPacketsDiscarded, MetricItems)
	UpfmoduleSet.DownLinkTotalInvalidPackets = metric.NewCounter(downLinkTotalInvalidPackets, MetricItems)
	UpfmoduleSet.DownLinkTotalDiscardedPackets = metric.NewCounter(downLinkTotalDiscardedPackets, MetricItems)

	//pfcp node
	UpfmoduleSet.PFCPAssociationSetupRequestTotalReceived = metric.NewCounter(pfcpAssociationSetupRequestTotalReceived, MetricItems)
	UpfmoduleSet.PFCPAssociationSetupResponseTotalSent = metric.NewCounter(pfcpAssociationSetupResponseTotalSent, MetricItems)

	UpfmoduleSet.HeartBeatRequestTotalReceived = metric.NewCounter(heartBeatRequestTotalReceived, MetricItems)
	UpfmoduleSet.HeartBeatResponseTotalSent = metric.NewCounter(heartBeatResponseTotalSent, MetricItems)
	UpfmoduleSet.HeartBeatResponseTotalReceived = metric.NewCounter(heartBeatResponseTotalReceived, MetricItems)
	UpfmoduleSet.HeartBeatRequestTotalSent = metric.NewCounter(heartBeatRequestTotalSent, MetricItems)

	UpfmoduleSet.PFCPAssociationUpdateRequestTotalReceived = metric.NewCounter(pfcpAssociationUpdateRequestTotalReceived, MetricItems)
	UpfmoduleSet.PFCPAssociationUpdateResponseTotalSent = metric.NewCounter(pfcpAssociationUpdateResponseTotalSent, MetricItems)
	UpfmoduleSet.PFCPAssociationUpdateResponseTotalReceived = metric.NewCounter(pfcpAssociationUpdateResponseTotalReceived, MetricItems)
	UpfmoduleSet.PFCPAssociationUpdateRequestTotalSent = metric.NewCounter(pfcpAssociationUpdateRequestTotalSent, MetricItems)

	UpfmoduleSet.PFCPNodeReportRequestTotalSent = metric.NewCounter(pfcpNodeReportRequestTotalSent, MetricItems)
	UpfmoduleSet.PFCPNodeReportResponseTotalReceived = metric.NewCounter(pfcpNodeReportResponseTotalReceived, MetricItems)

	UpfmoduleSet.PFCPAssociationReleaseRequestTotalReceived = metric.NewCounter(pfcpAssociationReleaseRequestTotalReceived, MetricItems)
	UpfmoduleSet.PFCPAssociationReleaseResponseTotalSent = metric.NewCounter(pfcpAssociationReleaseResponseTotalSent, MetricItems)

	UpfmoduleSet.PFCPPFDManagementRequestTotalReceived = metric.NewCounter(pfcpPFDManagementRequestTotalReceived, MetricItems)
	UpfmoduleSet.PFCPPFDManagementResponseTotalSent = metric.NewCounter(pfcpPFDManagementRequestTotalSent, MetricItems)

	//pfcp session
	UpfmoduleSet.PFCPSessionEstablishmentRequestTotalReceived = metric.NewCounter(pfcpSessionEstablishmentRequestTotalReceived, MetricItems)
	UpfmoduleSet.PFCPSessionEstablishmentResponseTotalSent = metric.NewCounter(pfcpSessionEstablishmentResponseTotalSent, MetricItems)

	UpfmoduleSet.PFCPSessionDeletionRequestTotalReceived = metric.NewCounter(pfcpSessionDeletionRequestTotalReceived, MetricItems)
	UpfmoduleSet.PFCPSessionDeletionResponseTotalSent = metric.NewCounter(pfcpSessionDeletionResponseTotalSent, MetricItems)

	UpfmoduleSet.PFCPSessionModificationRequestTotalReceived = metric.NewCounter(pfcpSessionModificationRequestTotalReceived, MetricItems)
	UpfmoduleSet.PFCPSessionModificationResponseTotalSent = metric.NewCounter(pfcpSessionModificationResponseTotalSent, MetricItems)

	UpfmoduleSet.PFCPSessionReportResponseTotalReceived = metric.NewCounter(pfcpSessionReportResponseTotalReceived, MetricItems)
	UpfmoduleSet.PFCPSessionReportRequestTotalSent = metric.NewCounter(pfcpSessionReportRequestTotalSent, MetricItems)

	//N3
	UpfmoduleSet.EchoRequest = metric.NewCounter(echoRequest, MetricItems)
	UpfmoduleSet.EchoResponse = metric.NewCounter(echoResponse, MetricItems)
	UpfmoduleSet.EndMarksMessages = metric.NewCounter(endMarksMessages, MetricItems)
	// pps
	// forward
	UpfmodulePISet.TotalPacketsPerSec = metric.NewMeter(totalPacketsPerSec, MetricItems)
	UpfmodulePISet.TotalBitsPerSec = metric.NewMeter(totalBitsPerSec, MetricItems)
	// up link
	UpfmodulePISet.UpLinkPacketsReceivedPerSec = metric.NewMeter(upLinkPacketsReceivedPerSec, MetricItems)
	UpfmodulePISet.UpLinkPacketsSentPerSec = metric.NewMeter(upLinkPacketsSentPerSec, MetricItems)
	UpfmodulePISet.UpLinkBitsSentPerSec = metric.NewMeter(upLinkBitsSentPerSec, MetricItems)
	UpfmodulePISet.UpLinkBitsReceivedPerSec = metric.NewMeter(upLinkBitsReceivedPerSec, MetricItems)
	// down link
	UpfmodulePISet.DownLinkPacketsReceivedPerSec = metric.NewMeter(downLinkPacketsReceivedPerSec, MetricItems)
	UpfmodulePISet.DownLinkPacketsSentPerSec = metric.NewMeter(downLinkPacketsSentPerSec, MetricItems)
	UpfmodulePISet.DownLinkBitsSentPerSec = metric.NewMeter(downLinkBitsSentPerSec, MetricItems)
	UpfmodulePISet.DownLinkBitsReceivedPerSec = metric.NewMeter(downLinkBitsReceivedPerSec, MetricItems)
	//pfcp node
	UpfmodulePISet.PFCPAssociationSetupRequestTotalReceivedPerSec = metric.NewMeter(pfcpAssociationSetupRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPAssociationSetupResponseTotalSentPerSec = metric.NewMeter(pfcpAssociationSetupResponseTotalSentPerSec, MetricItems)

	UpfmodulePISet.HeartBeatRequestTotalReceivedPerSec = metric.NewMeter(heartBeatRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.HeartBeatRequestTotalSentPerSec = metric.NewMeter(heartBeatRequestTotalSentPerSec, MetricItems)
	UpfmodulePISet.HeartBeatResponseTotalReceivedPerSec = metric.NewMeter(heartBeatResponseTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.HeartBeatResponseTotalSentPerSec = metric.NewMeter(heartBeatResponseTotalSentPerSec, MetricItems)

	UpfmodulePISet.PFCPAssociationUpdateRequestTotalReceivedPerSec = metric.NewMeter(pfcpAssociationUpdateRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPAssociationUpdateResponseTotalSentPerSec = metric.NewMeter(pfcpAssociationUpdateResponseTotalSentPerSec, MetricItems)
	UpfmodulePISet.PFCPAssociationUpdateResponseTotalReceivedPerSec = metric.NewMeter(pfcpAssociationUpdateResponseTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPAssociationUpdateRequestTotalSentPerSec = metric.NewMeter(pfcpAssociationUpdateRequestTotalSentPerSec, MetricItems)

	UpfmodulePISet.PFCPNodeReportRequestTotalSentPerSec = metric.NewMeter(pfcpNodeReportRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPNodeReportResponseTotalReceivedPerSec = metric.NewMeter(pfcpNodeReportResponseTotalSentPerSec, MetricItems)

	UpfmodulePISet.PFCPAssociationReleaseRequestTotalReceivedPerSec = metric.NewMeter(pfcpAssociationReleaseRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPAssociationReleaseResponseTotalSentPerSec = metric.NewMeter(pfcpAssociationReleaseResponseTotalSentPerSec, MetricItems)

	UpfmodulePISet.PFCPPFDManagementRequestTotalReceivedPerSec = metric.NewMeter(pfcpPFDManagementRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPPFDManagementResponseTotalSentPerSec = metric.NewMeter(pfcpPFDManagementResponseTotalSentPerSec, MetricItems)

	//pfcp session
	UpfmodulePISet.PFCPSessionEstablishmentRequestReceivedPerSec = metric.NewMeter(pfcpSessionEstablishmentRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPSessionEstablishmentResponseSentPerSec = metric.NewMeter(pfcpSessionEstablishmentResponseTotalSentPerSec, MetricItems)

	UpfmodulePISet.PFCPSessionModificationRequestReceivedPerSec = metric.NewMeter(pfcpSessionModificationRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPSessionModificationResponseSentPerSec = metric.NewMeter(pfcpSessionModificationResponseTotalSentPerSec, MetricItems)

	UpfmodulePISet.PFCPSessionDeletionRequestReceivedPerSec = metric.NewMeter(pfcpSessionDeletionRequestTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPSessionDeletionResponseSentPerSec = metric.NewMeter(pfcpSessionDeletionResponseTotalSentPerSec, MetricItems)

	UpfmodulePISet.PFCPSessionReportResponseReceivedPerSec = metric.NewMeter(pfcpSessionReportResponseTotalReceivedPerSec, MetricItems)
	UpfmodulePISet.PFCPSessionReportRequestSentPerSec = metric.NewMeter(pfcpSessionReportRequestTotalSentPerSec, MetricItems)

	//N3
	UpfmodulePISet.EchoRequestPerSec = metric.NewMeter(echoRequestPerSec, MetricItems)
	UpfmodulePISet.EchoResponsePerSec = metric.NewMeter(echoResponsePerSec, MetricItems)
	UpfmodulePISet.EndMarksMessagesPerSec = metric.NewMeter(endMarksMessagesPerSec, MetricItems)
	tickChan := time.Tick(TickDuration * time.Second)

	go func() {
		var PacketPI int64 // Value per interval

		for {
			select {
			case <-tickChan:
				////流量统计测试
				//var file *os.File
				//if _, err := os.Stat("counter.txt"); os.IsNotExist(err){
				//	file,err := os.Create("counter.txt")
				//	if err != nil{
				//		fmt.Println(err.Error())
				//	}
				//	file.Write([]byte("counter start:test1\n"))
				//}else{
				//	file,err := os.OpenFile("counter.txt",os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_TRUNC ,0644)
				//	if err != nil{
				//		fmt.Println(err.Error())
				//	}
				//	file.Write([]byte("counter start:test2\nUpLink:\n"))
				//	file.WriteString("UpLinkTotalPacketsReceived = "+strconv.Itoa(int(UpfmoduleSet.UpLinkTotalPacketsReceived.Count()))+"\n")
				//	file.WriteString("UpLinkTotalBitsReceived = "+strconv.Itoa(int(UpfmoduleSet.UpLinkTotalBitsReceived.Count()))+"\n")
				//	file.WriteString("UpLinkTotalPacketsSent = "+strconv.Itoa(int(UpfmoduleSet.UpLinkTotalPacketsSent.Count()))+"\n")
				//	file.WriteString("UpLinkTotalBitsSent = "+strconv.Itoa(int(UpfmoduleSet.UpLinkTotalBitsSent.Count()))+"\n")
				//	file.Write([]byte("DownLink:\n"))
				//	file.WriteString("DownLinkTotalPacketsReceived = "+strconv.Itoa(int(UpfmoduleSet.DownLinkTotalPacketsReceived.Count()))+"\n")
				//	file.WriteString("DownLinkTotalBitsReceived = "+strconv.Itoa(int(UpfmoduleSet.DownLinkTotalBitsReceived.Count()))+"\n")
				//	file.WriteString("DownLinkTotalPacketsSent = "+strconv.Itoa(int(UpfmoduleSet.DownLinkTotalPacketsSent.Count()))+"\n")
				//	file.WriteString("DownLinkTotalBitsSent = "+strconv.Itoa(int(UpfmoduleSet.DownLinkTotalBitsSent.Count()))+"\n")
				//}
				//defer file.Close()
				// 计算区间值P-I
				// 事件数Mark:当前计数 - 前一次计数

				// uplink
				PacketPI = IntervalIncrement(
					UpfmoduleSet.UpLinkTotalPacketsReceived.Count(),
					&UpfmoduleSet.UpLinkTotalPacketsReceivedPrevious)
				UpfmodulePISet.UpLinkPacketsReceivedPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.UpLinkTotalPacketsSent.Count(),
					&UpfmoduleSet.UpLinkTotalPacketsSentPrevious)
				UpfmodulePISet.UpLinkPacketsSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.UpLinkTotalBitsSent.Count(),
					&UpfmoduleSet.UpLinkTotalBitsSentPrevious)
				UpfmodulePISet.UpLinkBitsSentPerSec.Mark(PacketPI * 8)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.UpLinkTotalBitsReceived.Count(),
					&UpfmoduleSet.UpLinkTotalBitsReceivedPrevious)
				UpfmodulePISet.UpLinkBitsReceivedPerSec.Mark(PacketPI * 8)

				// downlink
				PacketPI = IntervalIncrement(
					UpfmoduleSet.DownLinkTotalPacketsReceived.Count(),
					&UpfmoduleSet.DownLinkTotalPacketsReceivedPrevious)
				UpfmodulePISet.DownLinkPacketsReceivedPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.DownLinkTotalPacketsSent.Count(),
					&UpfmoduleSet.DownLinkTotalPacketsSentPrevious)
				UpfmodulePISet.DownLinkPacketsSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.DownLinkTotalBitsSent.Count(),
					&UpfmoduleSet.DownLinkTotalBitsSentPrevious)
				UpfmodulePISet.DownLinkBitsSentPerSec.Mark(PacketPI * 8)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.DownLinkTotalBitsReceived.Count(),
					&UpfmoduleSet.DownLinkTotalBitsReceivedPrevious)
				UpfmodulePISet.DownLinkBitsReceivedPerSec.Mark(PacketPI * 8)
				//pfcp node
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationSetupRequestTotalReceived.Count(),
					&UpfmoduleSet.PFCPAssociationSetupRequestTotalReceivedPrevious)
				UpfmodulePISet.PFCPAssociationSetupRequestTotalReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationSetupResponseTotalSent.Count(),
					&UpfmoduleSet.PFCPAssociationSetupResponseTotalSentPrevious)
				UpfmodulePISet.PFCPAssociationSetupResponseTotalSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.HeartBeatRequestTotalReceived.Count(),
					&UpfmoduleSet.HeartBeatRequestTotalReceivedPrevious)
				UpfmodulePISet.HeartBeatRequestTotalReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.HeartBeatResponseTotalSent.Count(),
					&UpfmoduleSet.HeartBeatResponseTotalSentPrevious)
				UpfmodulePISet.HeartBeatResponseTotalSentPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.HeartBeatRequestTotalSent.Count(),
					&UpfmoduleSet.HeartBeatRequestTotalSentPrevious)
				UpfmodulePISet.HeartBeatRequestTotalSentPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.HeartBeatResponseTotalReceived.Count(),
					&UpfmoduleSet.HeartBeatResponseTotalReceivedPrevious)
				UpfmodulePISet.HeartBeatResponseTotalReceivedPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationUpdateRequestTotalReceived.Count(),
					&UpfmoduleSet.PFCPAssociationUpdateRequestTotalReceivedPrevious)
				UpfmodulePISet.PFCPAssociationUpdateRequestTotalReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationUpdateResponseTotalSent.Count(),
					&UpfmoduleSet.PFCPAssociationUpdateResponseTotalSentPrevious)
				UpfmodulePISet.PFCPAssociationUpdateResponseTotalSentPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationUpdateResponseTotalReceived.Count(),
					&UpfmoduleSet.PFCPAssociationUpdateResponseTotalReceivedPrevious)
				UpfmodulePISet.PFCPAssociationUpdateResponseTotalReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationUpdateRequestTotalSent.Count(),
					&UpfmoduleSet.PFCPAssociationUpdateRequestTotalSentPrevious)
				UpfmodulePISet.PFCPAssociationUpdateRequestTotalSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPNodeReportRequestTotalSent.Count(),
					&UpfmoduleSet.PFCPNodeReportRequestTotalSentPrevious)
				UpfmodulePISet.PFCPNodeReportRequestTotalSentPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPNodeReportResponseTotalReceived.Count(),
					&UpfmoduleSet.PFCPNodeReportResponseTotalReceivedPrevious)
				UpfmodulePISet.PFCPNodeReportResponseTotalReceivedPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationReleaseRequestTotalReceived.Count(),
					&UpfmoduleSet.PFCPAssociationReleaseRequestTotalReceivedPrevious)
				UpfmodulePISet.PFCPAssociationReleaseRequestTotalReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPAssociationReleaseResponseTotalSent.Count(),
					&UpfmoduleSet.PFCPAssociationReleaseResponseTotalSentPrevious)
				UpfmodulePISet.PFCPAssociationReleaseResponseTotalSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPPFDManagementRequestTotalReceived.Count(),
					&UpfmoduleSet.PFCPPFDManagementRequestTotalReceivedPrevious)
				UpfmodulePISet.PFCPPFDManagementRequestTotalReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPPFDManagementResponseTotalSent.Count(),
					&UpfmoduleSet.PFCPPFDManagementResponseTotalSentPrevious)
				UpfmodulePISet.PFCPPFDManagementResponseTotalSentPerSec.Mark(PacketPI)

				// pfcp session
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionEstablishmentRequestTotalReceived.Count(),
					&UpfmoduleSet.PFCPSessionEstablishmentRequestTotalReceivedPrevious)
				UpfmodulePISet.PFCPSessionEstablishmentRequestReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionEstablishmentResponseTotalSent.Count(),
					&UpfmoduleSet.PFCPSessionEstablishmentResponseTotalSentPrevious)
				UpfmodulePISet.PFCPSessionEstablishmentResponseSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionModificationRequestTotalReceived.Count(),
					&UpfmoduleSet.PFCPSessionModificationRequestTotalReceivedPrevious)
				UpfmodulePISet.PFCPSessionModificationRequestReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionModificationResponseTotalSent.Count(),
					&UpfmoduleSet.PFCPSessionModificationResponseTotalSentPrevious)
				UpfmodulePISet.PFCPSessionModificationResponseSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionDeletionRequestTotalReceived.Count(),
					&UpfmoduleSet.PFCPSessionDeletionRequestTotalReceivedPrevious)
				UpfmodulePISet.PFCPSessionDeletionRequestReceivedPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionDeletionResponseTotalSent.Count(),
					&UpfmoduleSet.PFCPSessionDeletionResponseTotalSentPrevious)
				UpfmodulePISet.PFCPSessionDeletionResponseSentPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionReportRequestTotalSent.Count(),
					&UpfmoduleSet.PFCPSessionReportRequestTotalSentPrevious)
				UpfmodulePISet.PFCPSessionReportRequestSentPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.PFCPSessionReportResponseTotalReceived.Count(),
					&UpfmoduleSet.PFCPSessionReportResponseTotalReceivedPrevious)
				UpfmodulePISet.PFCPSessionReportResponseReceivedPerSec.Mark(PacketPI)

				//N3
				PacketPI = IntervalIncrement(
					UpfmoduleSet.EchoRequest.Count(),
					&UpfmoduleSet.EchoRequestPrevious)
				UpfmodulePISet.EchoRequestPerSec.Mark(PacketPI)
				PacketPI = IntervalIncrement(
					UpfmoduleSet.EchoResponse.Count(),
					&UpfmoduleSet.EchoResponsePrevious)
				UpfmodulePISet.EchoResponsePerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.EndMarksMessages.Count(),
					&UpfmoduleSet.EndMarksMessagesPrevious)
				UpfmodulePISet.EndMarksMessagesPerSec.Mark(PacketPI)

				// forward
				// 计算转发总量
				UpfmoduleSet.TotalPackets.Clear()
				UpfmoduleSet.TotalPackets.Inc(UpfmoduleSet.UpLinkTotalPacketsSentPrevious + UpfmoduleSet.DownLinkTotalPacketsSentPrevious)

				UpfmoduleSet.TotalBits.Clear()
				UpfmoduleSet.TotalBits.Inc(UpfmoduleSet.UpLinkTotalBitsSentPrevious + UpfmoduleSet.DownLinkTotalBitsSentPrevious)

				UpfmoduleSet.UpLinkTotalDiscardedPackets.Clear()
				UpfmoduleSet.UpLinkTotalDiscardedPackets.Inc(
					UpfmoduleSet.UpLinkTotalReceivedPacketsDiscarded.Count() +
						UpfmoduleSet.UpLinkTotalSentPacketsDiscarded.Count() +
						UpfmoduleSet.UpLinkTotalInvalidPackets.Count())

				UpfmoduleSet.DownLinkTotalDiscardedPackets.Clear()
				UpfmoduleSet.DownLinkTotalDiscardedPackets.Inc(UpfmoduleSet.DownLinkTotalReceivedPacketsDiscarded.Count() +
					UpfmoduleSet.DownLinkTotalSentPacketsDiscarded.Count() +
					UpfmoduleSet.DownLinkTotalInvalidPackets.Count())

				UpfmoduleSet.TotalDiscardedPackets.Clear()
				UpfmoduleSet.TotalDiscardedPackets.Inc(UpfmoduleSet.UpLinkTotalDiscardedPackets.Count() + UpfmoduleSet.DownLinkTotalDiscardedPackets.Count())

				PacketPI = IntervalIncrement(
					UpfmoduleSet.TotalPackets.Count(),
					&UpfmoduleSet.TotalPacketsPrevious)
				UpfmodulePISet.TotalPacketsPerSec.Mark(PacketPI)

				PacketPI = IntervalIncrement(
					UpfmoduleSet.TotalBits.Count(),
					&UpfmoduleSet.TotalBitsPrevious)
				UpfmodulePISet.TotalBitsPerSec.Mark(PacketPI * 8)

			}
		}
	}()
	// session pps
	go upfSessionPps()
	// 上报到lems
	// StartPMReport()

	return MetricItems, nil
}

// Calculated interval increment
func IntervalIncrement(Current int64, Previous *int64) int64 {
	PacketPI := Current - *Previous
	*Previous = Current
	return PacketPI
}

func Log(r metric.Registry) {
	//metric.Log(r, 5e9)
	//r.Get(metric.UpLinkReceivedPacketPerS).(metrics.Meter).Count()
	//
	/*pms := webTypes.NewNfPerformanceData()
	pms.NfNo = configure.LemsUpfAgentConf.NfNo.UpfNfNo
	pms.Params = append(pms.Params, webTypes.Param{111, 100})
	*/ //agent.StartPerformanceReport(5e9)
	//time.Sleep(10e9)
	//agent.StopPerformanceReport()
}

func SessionLog(seid uint64) {

	if SessionCounterStart == true {

		n4cxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(seid))
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to get N4 Context:%s", err)
			return
		}
		metric.Log(n4cxt.MetricItems, 7e9)
	}
}

func GetSeidFromIp(ip string) (uint64, error) {

	return pdr.GetSeidFromIp(ip)
}

func GetSeidFromTeid(teid uint32) (uint64, error) {

	return pdr.GetSeidFromTeid(teid)
}
