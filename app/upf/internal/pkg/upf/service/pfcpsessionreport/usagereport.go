/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/5/6 10:28
* Description:
 */
package pfcpsessionreport

import (
	"errors"
	"fmt"
	"lite5gc/cmn/message/pfcp"
	"lite5gc/cmn/metric"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/upf/context/n4context"
	"lite5gc/upf/cp/n4layer"
	"lite5gc/upf/cp/n4node"
	"lite5gc/upf/metrics"
	"lite5gc/upf/service/pfcpsessionreport/sessionreportdef"
	"net"
	"time"
)

func StartUsageReportServer(upfCtxt *types.AppContext) error {
	rlogger.FuncEntry(types.ModeleUpfUsageReport, nil)
	// create a receive message server
	ReportServer := sessionreportdef.ReportServer
	if ReportServer == nil {
		//panic("Failed to apply for memory")
		return errors.New("Failed to apply for memory")
	}
	// 处理Usage Report请求
	go StartUsageReportHandle(upfCtxt, ReportServer)
	go StartInactiveReportHandle()
	return nil
}
func StartInactiveReportHandle() {
	// 每6s遍历计算一次
	tickChan := time.Tick(6 * time.Second)
	for {
		select {
		case <-tickChan:
			// 遍历N4上下文，对每个session 计算 不活跃时间
			n4List, err := n4context.ValuesOfN4ContextTbl(n4context.N4SessionIDCxtType)
			if err != nil {
				rlogger.Trace(types.ModeleUpfUsageReport, rlogger.ERROR, nil, "Failed to get N4 Context:%s", err)
				return
			}
			for _, v := range n4List {
				//数据包无新增时开始周期读秒
				//rlogger.Trace(types.ModeleUpfUsageReport, rlogger.INFO, nil, "N6 receive pkt num:%d,last num:%d",metric.Get(metrics.DownLinkSessionReceivedPacket, v.MetricItems).Count(),
				//空指针注释掉
				//	metric.Get(metrics.LastSessionReportpkt, v.MetricItems).Count())
				if metric.Get(metrics.DownLinkSessionReceivedPacket, v.MetricItems) != nil &&
					metric.Get(metrics.LastSessionReportpkt, v.MetricItems) != nil &&
					metric.Get(metrics.DownLinkSessionReceivedPacket, v.MetricItems).Count() == metric.Get(metrics.LastSessionReportpkt, v.MetricItems).Count() &&
					metrics.SessionCounterStart == true {
					// 在每个MetricItems中计算不活跃时间
					if (metric.Get(metrics.SetupSessiontime, v.MetricItems) != nil &&
						metric.Get(metrics.SetupSessiontime, v.MetricItems).Count() != 0 &&
						v.UserPlaneInactivityTimer != nil &&
						time.Now().Unix()+2209017600-metric.Get(metrics.SetupSessiontime, v.MetricItems).Count() >= int64(v.UserPlaneInactivityTimer.TimerValue)) ||
						(metric.Get(metrics.NowSessionDataTime, v.MetricItems) != nil &&
							metric.Get(metrics.NowSessionDataTime, v.MetricItems).Count() != 0 &&
							v.UserPlaneInactivityTimer != nil &&
							time.Now().Unix()+2209017600-metric.Get(metrics.NowSessionDataTime, v.MetricItems).Count() >= int64(v.UserPlaneInactivityTimer.TimerValue)) {
						_, err := n4node.GetNodeApi(v.SmfSEID.IPv4Addr.String())
						if err != nil {
							rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
								"The corresponding processing node does not exist(%s),err:%s", v.SmfSEID.IPv4Addr, err)
							continue
						}
						sendInactivereportRequestMsg(v)
						metric.Get(metrics.NowSessionDataTime, v.MetricItems).Clear()
						metric.Get(metrics.NowSessionDataTime, v.MetricItems).Inc(time.Now().Unix() + 2209017600)
						metric.Get(metrics.SetupSessiontime, v.MetricItems).Clear()
					}
				} else { //数据包增加时，重置LastSessionReportpkt计数
					if metric.Get(metrics.LastSessionReportpkt, v.MetricItems) != nil {
						metric.Get(metrics.LastSessionReportpkt, v.MetricItems).Clear()
						metric.Get(metrics.LastSessionReportpkt, v.MetricItems).Inc(metric.Get(metrics.DownLinkSessionReceivedPacket, v.MetricItems).Count())
					}
				}
			}
		}
	}
}

func sendInactivereportRequestMsg(urrInfo *n4context.N4SessionContext) bool {
	reqFlowN4, err := n4layer.CreateInactivereportRequestMsg(urrInfo)
	if err != nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, urrInfo, "Failed to Create N4 session release request message :%s", err)
		return false
	}
	var resFlowN4 pfcp.SessionReportResponse
	if urrInfo.SmfSEID.IPv6Addr != nil {
		peerAddrFlow := &net.UDPAddr{IP: urrInfo.SmfSEID.IPv6Addr,
			Port: configure.UpfConf.N4.Smf.Port}
		err = n4layer.SendMsgI(reqFlowN4, &resFlowN4, peerAddrFlow)
		if err != nil {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, urrInfo, "Failed to send N4 message:%s", err)
			return false
		}
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, urrInfo, "Send N4 Inactivereport request message to :%s", peerAddrFlow)
		return true
	}
	peerAddrFlow := &net.UDPAddr{IP: urrInfo.SmfSEID.IPv4Addr,
		Port: configure.UpfConf.N4.Smf.Port}
	err = n4layer.SendMsgI(reqFlowN4, &resFlowN4, peerAddrFlow)
	if err != nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, urrInfo, "Failed to send N4 message:%s", err)
		return false
	}
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, urrInfo, "Send N4 Inactivereport request message to :%s", peerAddrFlow)
	return true
}

func StartUsageReportHandle(upfCtxt *types.AppContext, server *sessionreportdef.ReportHandle) {
	fmt.Printf("start usage report\n")
	rlogger.FuncEntry(types.ModeleUpfUsageReport, nil)
	rlogger.Trace(types.ModeleUpfUsageReport, rlogger.INFO, nil, "usage report server routine start")
	upfCtxt.Wg.Add(1)
	defer upfCtxt.Wg.Done()

	for {
		select {
		case <-upfCtxt.Ctx.Done():
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "usage report server routine exit")
			return

		case msg := <-server.RevReportInfoChan:
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.DEBUG, nil, "start usage report,receive usage info :%+v", *msg)
			// 启动 usage report
			err := ReportHandle(msg)
			if err != nil {
				rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, nil, "Failed to start usage report sending :%+v", *msg)
			}
		}
	}
}

func ReportHandle(urrInfo *n4context.N4SessionContext) error {
	rlogger.FuncEntry(types.ModuleUpfServiceEcho, nil)

	// 发送Report 消息
	ReportSetup(urrInfo)

	return nil
}

func ReportSetup(urrInfo *n4context.N4SessionContext) {
	sendreportRequestMsg(urrInfo)
}

func sendreportRequestMsg(urrInfo *n4context.N4SessionContext) bool {
	reqFlowN4, err := n4layer.CreateflowReportRequestMsg(urrInfo)
	if err != nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, urrInfo, "Failed to Create N4 session release request message :%s", err)
		return false
	}
	metric.Get(metrics.LastSessionReportTime, urrInfo.MetricItems).Clear()
	metric.Get(metrics.LastSessionReportTime, urrInfo.MetricItems).Inc(time.Now().Unix() + 2209017600) //2209017600为1900年到1970年秒数差
	var resFlowN4 pfcp.SessionReportResponse
	if urrInfo.SmfSEID.IPv6Addr != nil {
		peerAddrFlow := &net.UDPAddr{IP: urrInfo.SmfSEID.IPv6Addr,
			Port: configure.UpfConf.N4.Smf.Port}
		err = n4layer.SendMsgI(reqFlowN4, &resFlowN4, peerAddrFlow)
		if err != nil {
			rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, urrInfo, "Failed to send N4 message:%s", err)
			return false
		}
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, urrInfo, "Send N4 report request message to :%s", peerAddrFlow)
		return true
	}
	peerAddrFlow := &net.UDPAddr{IP: urrInfo.SmfSEID.IPv4Addr,
		Port: configure.UpfConf.N4.Smf.Port}
	err = n4layer.SendMsgI(reqFlowN4, &resFlowN4, peerAddrFlow)
	if err != nil {
		rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.ERROR, urrInfo, "Failed to send N4 message:%s", err)
		return false
	}
	rlogger.Trace(types.ModuleUpfServiceEcho, rlogger.INFO, urrInfo, "Send N4 report request message to :%s", peerAddrFlow)
	return true
}
