/*
* Copyright(C),2020‐2022
* Author: Lenovo
* Date: 2021/3/31 10:38
* Description:
 */
package signaldef

import (
	"lite5gc/upf/context/gnbcontext"
)

const (
	Chancap = 1000 // receive channel buffer //1000
)

// echo 启动信息
/*type GnbInfo struct {
	Ip    net.UDPAddr
	Start bool
}*/

// echo 业务触发通道
type EchoHandle struct {
	Gnb            []gnbcontext.GnbInfo
	RevGnbInfoChan chan *gnbcontext.GnbInfo
}

func NewEchoHandle() *EchoHandle {
	return &EchoHandle{
		RevGnbInfoChan: make(chan *gnbcontext.GnbInfo, Chancap),
	}
}

// ReceiveMsg: Send the received message to the channel
func (s *EchoHandle) ReceiveMsg(msgCxt *gnbcontext.GnbInfo) bool {
	select {
	case s.RevGnbInfoChan <- msgCxt:
		return true
	default:
		return false //队列已满，消息丢弃

	}
	//fmt.Printf("chan: %s",<-s.MsgListChan)
}

// Server
var EchoServer = NewEchoHandle()
