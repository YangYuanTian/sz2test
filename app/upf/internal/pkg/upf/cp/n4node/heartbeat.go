/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/3/18 16:29
* Description:
 */
package n4node

import (
	"context"
	"fmt"
	"time"
	"upf/internal/pkg/cmn/message/pfcp"
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types"
	. "upf/internal/pkg/upf/cp/n4node/typedef"
	"upf/internal/pkg/upf/metrics"
)

// TS 29.244
// 6.2.2	Heartbeat Procedure
func HeartbeatSetup(n *Node) {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//1、在节点创建后启动3s定时器
	t1 := time.NewTimer(pfcpv1.T1)

	cxt, cancel := context.WithCancel(context.Background())
	n.NTimer.T1Cancel = cancel // stop timer
	//reSetcxt, reset := context.WithCancel(context.Background())
	reSetcxt := make(chan struct{}, 1)
	reset := func() {
		reSetcxt <- struct{}{}
	}
	// reset timer
	n.NTimer.T1Reset = reset

	n.NTimer.T1 = t1

	for {
		select {
		case <-reSetcxt:
			//3、收到节点内的任何消息（除节点释放消息），重置定时器
			t1.Reset(pfcpv1.T1)
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "node:%s,reset Heartbeat", n.NodeID)
			//rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "node:%s,reset Heartbeat timer ", n.NodeID, t1)

		case <-cxt.Done(): // 关闭chan，不阻塞
			//4、释放节点后，关闭心跳定时器
			t1.Stop()
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "node:%s,stop Heartbeat", n.NodeID)
			return
		case <-t1.C:
			//	发送心跳消息,一个协程处理发送处理
			go sendHeartbeatMsg(n)
			t1.Reset(pfcpv1.T1)
		}
	}
}

// 7.4.2.1	Heartbeat Request
func HeartbeatRequestCreate(node *Node) *pfcpv1.Message {
	//rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	node.SequenceNumber += 1
	msg := &pfcpv1.Message{}
	request := &pfcp.HeartbeatRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Heartbeat_Request,
			Length:         0, // 编码后填充
			SequenceNumber: node.SequenceNumber},
	}
	//Mandatory IE
	request.IE = &pfcp.IEHeartbeatRequest{}
	request.IE.RecoveryTimeStamp = &pfcp.IERecoveryTimeStamp{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeRecoveryTimeStamp,
			Length: 4},
		RecoveryTimeStamp: time.Now(),
	}

	// 构造待编码消息
	// Encoding message filling
	err := msg.HeaderSet(request.PfcpHeader)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Pfcp msg filling err %s", err)
	}
	err = msg.BodySet(request)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Pfcp msg filling err %s", err)
	}

	//rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, msg.String())

	return msg
}

func sendHeartbeatMsg(n *Node) { // f 是非阻塞调用
	//rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//2、3s到发送heartbeat消息
	// 创建消息
	msg := HeartbeatRequestCreate(n)
	// 编码发送
	data, err := msg.Marshal()
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Pfcp msg marshal err %s", err)
	}

	err = n.SendUdpMsg(data)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Pfcp msg send err %s", err)
		return
	}
	metrics.UpfmoduleSet.HeartBeatRequestTotalSent.Inc(1)
	// 启动响应超时重传
	err = HeartbeatTimeoutRetransmission(n, data)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Pfcp msg Timeout retransmission err: %s", err)
	}
	metrics.UpfmoduleSet.HeartBeatRequestTotalSent.Inc(1)
	//设置流程的当前状态

}
func HeartbeatTimeoutRetransmission(n *Node, data []byte) error {
	//rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//1、发送请求后，启动超时定时器
	cxt, cancel := context.WithCancel(context.Background())
	n.NTimer.T1RetransCancel = cancel
	pfcpv1.T2 = pfcpv1.T1 / 5
	t2 := time.NewTimer(pfcpv1.T2)
	var RetrCount = 0

	for {
		select {
		case <-cxt.Done():
			//2、收到响应消息，关闭定时器
			t2.Stop()
			RetrCount = 0 //important point
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "turn off retransmission,Heartbeat")
			return nil
		case <-t2.C:
			if RetrCount == pfcpv1.MaxRetransT2 {
				//3、超时后，重发请求，发送3次，无响应，上报失败响应
				t2.Stop()
				// 对端没有响应，关闭心跳发送，删除节点
				//设置node的当前状态
				n.NFsm.NodeFsm.Bfsm.SetState(StateNodeActive)
				err := n.NFsm.NodeFsm.Bfsm.Event(EventNodeTimeout, n)
				if err != nil {
					rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Setting Status error %s", err)
				}
				rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "no response from peer,Heartbeat %s", n.PeerAddr.String())
				return fmt.Errorf("timeout")
			}
			t2.Reset(pfcpv1.T2)
			{
				// 发送消息到 udp server，使用UDP conn 的双工发送
				err := n.SendUdpMsg(data)
				if err != nil {
					rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "message sending failed from Heartbeat:%s,peer(%s)", err, n.PeerAddr)
					return err
				}
				RetrCount += 1
				rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil,
					"SendN4UdpMsg to Peer : <%s>--><%s>: %#x\n", n.Server.UdpConn.LocalAddr(), n.PeerAddr, data)
			}
		}
	}
}

// AssociationSetupRequest
func TimeoutRetransmission(n *Node, data []byte) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//1、发送请求后，启动超时定时器
	cxt, cancel := context.WithCancel(context.Background())
	n.NTimer.T2Cancel = cancel
	t2 := time.NewTimer(pfcpv1.T2)
	var RetrCount = 0

	for {
		select {
		case <-cxt.Done():
			//2、收到响应消息，关闭定时器
			t2.Stop()
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "turn off retransmission")
			return nil
		case <-t2.C:
			if RetrCount == pfcpv1.MaxRetransT2 {
				//3、超时后，重发请求，发送3次，无响应，上报失败响应
				t2.Stop()
				rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "no response from peer", n.PeerAddr.String())
				//设置node的当前状态
				n.NFsm.NodeFsm.Bfsm.SetState(StateNodeRelease)
				n.NFsm.NodeFsm.Bfsm.Event(EventNodeReleaseAck, n)
				rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "no response from peer,Heartbeat", n.PeerAddr.String())
				return fmt.Errorf("timeout")
			}
			t2.Reset(pfcpv1.T2)
			{
				// 发送消息到 udp server，使用UDP conn 的双工发送
				err := n.SendUdpMsg(data)
				if err != nil {
					rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "message sending failed:%s,peer(%s)", err, n.PeerAddr)
					return err
				}
				RetrCount += 1
				rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil,
					"SendN4UdpMsg to Peer : <%s>--><%s>: %#x\n", n.Server.UdpConn.LocalAddr(), n.PeerAddr, data)
			}
		}
	}
}

// 7.4.2.2	Heartbeat Response
func HeartbeatResponseCreate(req *pfcp.HeartbeatRequest) *pfcpv1.Message {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	msg := &pfcpv1.Message{}
	response := &pfcp.HeartbeatResponse{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Heartbeat_Response,
			Length:         0, // 编码后填充
			SequenceNumber: req.PfcpHeader.SequenceNumber},
	}
	//Mandatory IE
	response.IE = &pfcp.IERecoveryTimeStamp{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeRecoveryTimeStamp,
			Length: 4},
		RecoveryTimeStamp: req.IE.RecoveryTimeStamp.RecoveryTimeStamp,
	}

	// 构造待编码消息
	// Encoding message filling
	msg.HeaderSet(response.PfcpHeader)
	msg.BodySet(response)

	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, msg.String())

	return msg
}

func HandleHeartbeatResponse(n *Node, res *pfcp.HeartbeatResponse) error {
	//rlogger.FuncEntry(types.ModuleSmfN4, nil)
	if n == nil || res == nil {
		return fmt.Errorf("Illegal message")
	}
	// 节点状态不变，重置心跳定时器
	if n.NTimer.T1RetransCancel != nil {
		n.NTimer.T1RetransCancel()
	}
	// 节点消息匹配检查
	if res.PfcpHeader.SequenceNumber != n.SequenceNumber {
		return fmt.Errorf("response msg mismatch")
	}
	return nil
}
