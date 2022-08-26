package n4layer

import (
	"fmt"
	"net"
	"time"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/message/pfcp/pfcpudp"
	"upf/internal/pkg/cmn/message/pfcp/utils"
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
	"upf/internal/pkg/cmn/metric"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types/configure"
	utils2 "upf/internal/pkg/cmn/utils"
	"upf/internal/pkg/upf/context/n4context"
	"upf/internal/pkg/upf/context/pdrcontext"
	"upf/internal/pkg/upf/metrics"
)

// 作为client时，发起N4请求
// N4 Data Notification --> PFCP Session Report Request
func SessionReportRequest(n4Ctxt *n4context.N4SessionContext, dfCxt *pdrcontext.DataFlowContext) error {
	rlogger.FuncEntry(moduleTag, utils2.Seid(n4Ctxt.SEID))

	/*// get N4 context
	n4Ctxt, err := upfcontext.GetN4Context(upfcontext.N4SessionIDKey(dfCxt.SEID))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,  "Failure to get N4 Context:%s", err)
		// 本地无上下文，返回成功
		return nil
	}*/

	// 2.	The UPF sends an N4 session Report request message to the SMF.
	//*pfcp.SessionReleaseRequest
	reqN4, err := CreateReportRequestMsg(n4Ctxt, dfCxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Ctxt.SEID), "Failed to Create N4 session release request message :%s", err)
		return err
	}
	// 3 发送请求消息，异步处理响应
	var resN4 pfcp.SessionReportResponse
	if n4Ctxt.SmfSEID.IPv6Addr != nil {
		peerAddr := &net.UDPAddr{IP: n4Ctxt.SmfSEID.IPv6Addr,
			Port: configure.UpfConf.N4.Smf.Port}
		//upfIpN4Port := n4Ctxt.SmfSEID.IPv4Addr.String() + ":" + strconv.Itoa(configure.UpfConf.N4.Smf.Port) //":8806" //127.0.0.1
		err = SendMsgI(reqN4, &resN4, peerAddr)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Ctxt.SEID), "Failed to send N4 message:%s", err)
			return err
		}
		rlogger.Trace(moduleTag, rlogger.INFO, n4Ctxt, "Send N4 report request message to :%s", peerAddr)
		return nil
	}
	peerAddr := &net.UDPAddr{IP: n4Ctxt.SmfSEID.IPv4Addr,
		Port: configure.UpfConf.N4.Smf.Port}
	//upfIpN4Port := n4Ctxt.SEID.IPv4Addr.String() + ":" + strconv.Itoa(configure.UpfConf.N4.Smf.Port) //":8806" //127.0.0.1
	err = SendMsgI(reqN4, &resN4, peerAddr)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Ctxt.SEID), "Failed to send N4 message:%s", err)
		return err
	}
	rlogger.Trace(moduleTag, rlogger.INFO, n4Ctxt, "Send N4 report request message to :%s", peerAddr)
	// 4 响应成功,SMF响应失败消息
	/*if resN4.IE.Cause.CauseValue != pfcp.Cause_Request_accepted {
		return fmt.Errorf("Failed to Report N4 context,cause=%d", resN4.IE.Cause.CauseValue)
	}*/
	/*//1.	SMF receives the trigger to remove the N4 session context for the PDU Session.
	// delete N4 context
	// 在upf成功响应后释放本地 N4 context
	err = smfcontext.DeleteN4Context(smfcontext.N4SessionIDKey(seid))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,  "Failure to delete N4 Context:%s", err)
		return err
	}*/
	// 返回成功
	return nil
}

// IEsSessionReportRequest
func CreateReportRequestMsg(n4Ctxt *n4context.N4SessionContext,
	dfCxt *pdrcontext.DataFlowContext) (*pfcp.SessionReportRequest, error) {
	rlogger.FuncEntry(moduleTag, utils2.Seid(n4Ctxt.SEID))
	var reqN4 pfcp.SessionReportRequest
	// 获取UPF的SEID
	reqN4.PfcpHeader.Set()
	reqN4.PfcpHeader.MessageType = pfcp.PFCP_Session_Report_Request
	reqN4.PfcpHeader.SEID = n4Ctxt.SmfSEID.SEID
	reqN4.PfcpHeader.SequenceNumber = SequenceNumber
	SequenceNumber += 1

	// 2 请求消息构造
	reqN4.IE = pfcp.IEsSessionReportRequest{}
	// todo
	//reqN4.IE.ReportType.Set(pfcp.DLDR)
	reqN4.IE.ReportType.Type = pfcp.IeTypeReportType
	reqN4.IE.ReportType.DLDR = true

	//set optional IE
	reqN4.IE.IeFlags.Set(pfcp.IeTypeDownlinkDataReport)
	reqN4.IE.DownlinkDataReport = &pfcp.IEDownlinkDataReport{}
	reqN4.IE.DownlinkDataReport.Set()
	reqN4.IE.DownlinkDataReport.PDRID.Set(dfCxt.RuleID)

	reqN4.IE.DownlinkDataReport.IeFlags.Set(pfcp.IeTypeDownlinkDataServiceInformation)
	reqN4.IE.DownlinkDataReport.DLDataServiceInfo = &pfcp.IEDLDataServiceInfo{}
	reqN4.IE.DownlinkDataReport.DLDataServiceInfo.Set()

	reqN4.IE.DownlinkDataReport.DLDataServiceInfo.QFI = dfCxt.DP.QFI
	//reqN4.IE.DownlinkDataReport.DLDataServiceInfo.Flag &= pfcp.QFII_Flag
	reqN4.IE.DownlinkDataReport.DLDataServiceInfo.QFII = true

	if utils.IsSetByte(dfCxt.DP.PPP, 7) { // todo 定义7
		reqN4.IE.DownlinkDataReport.DLDataServiceInfo.PPIValue = dfCxt.DP.PPI
		//reqN4.IE.DownlinkDataReport.DLDataServiceInfo.Flag &= pfcp.QFII_Flag
		reqN4.IE.DownlinkDataReport.DLDataServiceInfo.PPI = true
	}

	return &reqN4, nil
}

// create流量统计report
func CreateflowReportRequestMsg(n4Ctxt *n4context.N4SessionContext) (*pfcp.SessionReportRequest, error) {
	rlogger.FuncEntry(moduleTag, n4Ctxt)
	urseqn := metric.Get(metrics.URSEQN, n4Ctxt.MetricItems)
	if urseqn == nil {
		return nil, fmt.Errorf("metric is null")
	}
	urseqn.Inc(1)
	var reqN4 pfcp.SessionReportRequest
	// 获取UPF的SEID
	reqN4.PfcpHeader.Set()
	reqN4.PfcpHeader.MessageType = pfcp.PFCP_Session_Report_Request
	reqN4.PfcpHeader.SEID = n4Ctxt.SmfSEID.SEID
	reqN4.PfcpHeader.SequenceNumber = SequenceNumber
	SequenceNumber += 1

	// 2 请求消息构造
	reqN4.IE = pfcp.IEsSessionReportRequest{}
	// todo
	//reqN4.IE.ReportType.Set(pfcp.USAR)
	reqN4.IE.ReportType.Type = pfcp.IeTypeReportType
	reqN4.IE.ReportType.USAR = true

	//set optional IE
	reqN4.IE.IeFlags.Set(pfcp.IeTypeUsageReportRequest)
	reqN4.IE.UsageReport = &pfcp.IEUsageReportWithinRepReq{}
	reqN4.IE.UsageReport.Set(1)
	reqN4.IE.UsageReport.URRID.Set(n4Ctxt.URRs[0].URRID.URRIDValue)
	reqN4.IE.UsageReport.URSEQN.Set(uint32(metric.Get(metrics.URSEQN, n4Ctxt.MetricItems).Count()))
	reqN4.IE.UsageReport.UsageReportTrigger.Set()
	reqN4.IE.UsageReport.UsageReportTrigger.VOLTH = n4Ctxt.URRs[0].ReportingTriggers.VOLTH

	reqN4.IE.UsageReport.StartTime = &pfcp.IEStartTime{}
	reqN4.IE.UsageReport.StartTime.Set()

	reqN4.IE.UsageReport.EndTime = &pfcp.IEEndTime{}
	reqN4.IE.UsageReport.EndTime.Set()

	//Get traffic statistics
	reqN4.IE.UsageReport.VolumeMeasurement = &pfcp.IEVolumeMeasurement{}
	reqN4.IE.UsageReport.IeFlags.Set(pfcp.IeTypeVolumeMeasurement)
	reqN4.IE.UsageReport.VolumeMeasurement.Set()
	reqN4.IE.UsageReport.VolumeMeasurement.DLVOL = true
	reqN4.IE.UsageReport.VolumeMeasurement.ULVOL = true
	reqN4.IE.UsageReport.VolumeMeasurement.TOVOL = n4Ctxt.URRs[0].VolumeThreshold.TOVOL
	//TotalVolume,UplinkVolume,DownlinkVolume单位为字节
	reqN4.IE.UsageReport.VolumeMeasurement.TotalVolume = uint64(metric.Get(metrics.UpLinkSessionBitsReceivedSub, n4Ctxt.MetricItems).Count()+
		metric.Get(metrics.DownLinkSessionBitsReceivedSub, n4Ctxt.MetricItems).Count()) / 8
	reqN4.IE.UsageReport.VolumeMeasurement.UplinkVolume = uint64(metric.Get(metrics.UpLinkSessionBitsReceivedSub, n4Ctxt.MetricItems).Count()) / 8
	reqN4.IE.UsageReport.VolumeMeasurement.DownlinkVolume = uint64(metric.Get(metrics.DownLinkSessionBitsReceivedSub, n4Ctxt.MetricItems).Count()) / 8

	reqN4.IE.UsageReport.DurationMeasurement = &pfcp.IEDurationMeasurement{}
	reqN4.IE.UsageReport.DurationMeasurement.Set()

	reqN4.IE.UsageReport.AppDetectionInformation = &pfcp.IEAppDetectionInformation{}

	reqN4.IE.UsageReport.UEIPaddress = &pfcp.IEUEIPaddress{}
	reqN4.IE.UsageReport.UEIPaddress.Set()

	reqN4.IE.UsageReport.NetworkInstance = &pfcp.IENetworkInstance{}
	reqN4.IE.UsageReport.NetworkInstance.Set()

	reqN4.IE.UsageReport.IeFlags.Set(pfcp.IeTypeTimeOfFirstPacket)
	reqN4.IE.UsageReport.TimeofFirstPacket = &pfcp.IETimeofFirstPacket{}
	reqN4.IE.UsageReport.TimeofFirstPacket.Set()
	if metric.Get(metrics.LastSessionReportTime, n4Ctxt.MetricItems).Count() == 0 {
		reqN4.IE.UsageReport.TimeofFirstPacket.TimeFirstPacket = uint32(metric.Get(metrics.FirstSessionReportTime, n4Ctxt.MetricItems).Count())
	} else {
		reqN4.IE.UsageReport.TimeofFirstPacket.TimeFirstPacket = uint32(metric.Get(metrics.LastSessionReportTime, n4Ctxt.MetricItems).Count())
	}

	reqN4.IE.UsageReport.IeFlags.Set(pfcp.IeTypeTimeOfLastPacket)
	reqN4.IE.UsageReport.TimeofLastPacket = &pfcp.IETimeofLastPacket{}
	reqN4.IE.UsageReport.TimeofLastPacket.Set()
	reqN4.IE.UsageReport.TimeofLastPacket.TimeLastPacket = uint32(time.Now().Unix() + 2209017600) //2209017600为1900年到1970年秒数差

	reqN4.IE.UsageReport.UsageInformation = &pfcp.IEUsageInformation{}
	reqN4.IE.UsageReport.UsageInformation.Set()

	reqN4.IE.UsageReport.QueryURRReference = &pfcp.IEQueryURRReference{}
	reqN4.IE.UsageReport.QueryURRReference.Set(1)

	reqN4.IE.UsageReport.EventTimeStamp = &pfcp.IEEventTimeStamp{}
	reqN4.IE.UsageReport.EventTimeStamp.Set(1)

	return &reqN4, nil
}

// Inactive report
func CreateInactivereportRequestMsg(n4Ctxt *n4context.N4SessionContext) (*pfcp.SessionReportRequest, error) {
	rlogger.FuncEntry(moduleTag, n4Ctxt)
	var reqN4 pfcp.SessionReportRequest
	// 获取UPF的SEID
	reqN4.PfcpHeader.Set()
	reqN4.PfcpHeader.MessageType = pfcp.PFCP_Session_Report_Request
	reqN4.PfcpHeader.SEID = n4Ctxt.SmfSEID.SEID
	reqN4.PfcpHeader.SequenceNumber = SequenceNumber
	SequenceNumber += 1

	// 2 请求消息构造
	reqN4.IE = pfcp.IEsSessionReportRequest{}
	// todo
	//reqN4.IE.ReportType.Set(pfcp.UPIR)
	reqN4.IE.ReportType.Type = pfcp.IeTypeReportType
	reqN4.IE.ReportType.UPIR = true

	return &reqN4, nil
}

func SendMsgI(req *pfcp.SessionReportRequest, res interface{}, peerAddr *net.UDPAddr) error {
	rlogger.FuncEntry(moduleTag, utils2.Seid(req.PfcpHeader.SEID))
	// pfcp encode
	request := pfcpv1.Message{}
	request.HeaderSet(req.PfcpHeader)
	request.BodySet(req)
	data, err := request.Marshal()
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID), "Pfcp msg marshal err %s", err)
		return err
	}
	UdpConn := pfcpudp.PfcpServer.UdpConn
	_, err = UdpConn.WriteToUDP(data, peerAddr)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID), "Pfcp msg send err %s", err)
		return err
	}
	//fmt.Printf("SessionModifyResponse: %+v\n", resN4)

	return nil
}

func SessionReportResponseHandle(res *pfcp.SessionReportResponse) error {
	// 4 响应成功,SMF响应失败消息
	if res.IE.Cause.CauseValue != pfcp.Cause_Request_accepted {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(res.PfcpHeader.SEID),
			"Failed to Session Report Response, cause: %d", res.IE.Cause.CauseValue)
		return fmt.Errorf("Failed to Report N4 context,cause=%d", res.IE.Cause.CauseValue)
	}

	return nil
}
