/*
* Copyright(C),2020‐2022
* Author: chencheng
* Date: 2021/5/6 10:38
* Description:
 */
package sessionreportdef

import (
	"lite5gc/upf/context/n4context"
)

// UsageReport 业务触发通道
type ReportHandle struct {
	RevReportInfoChan chan *n4context.N4SessionContext
}

func NewReportHandle() *ReportHandle {
	return &ReportHandle{
		//同时处理的session上限为10000
		RevReportInfoChan: make(chan *n4context.N4SessionContext, 10000),
	}
}

// ReceiveMsg: Send the received message to the channel
func (s *ReportHandle) ReceiveMsg(msgCxt *n4context.N4SessionContext) bool {
	select {
	case s.RevReportInfoChan <- msgCxt:
		return true
	default:
		return false //队列已满，消息丢弃

	}
	//fmt.Printf("chan: %s",<-s.MsgListChan)
}

// Server
var ReportServer = NewReportHandle()
