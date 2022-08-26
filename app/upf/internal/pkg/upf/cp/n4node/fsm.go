package n4node

import (
	"fmt"
	"upf/internal/pkg/cmn/fsm"
	"upf/internal/pkg/cmn/message/pfcp"
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types"
	. "upf/internal/pkg/upf/cp/n4node/typedef"
)

// NewNodeProcFSM return a NodeProcFSM pointer after create
// for each sc go route, make sure only one fsm
func NewNodeFSM() (*NodeFSM, error) {

	bfsm := fsm.CreateFsm(StateNodeStart)

	nodeFsm := &NodeFSM{}
	nodeFsm.Bfsm = bfsm

	err := initStateModel(nodeFsm)
	if err != nil {
		fmt.Println("Failed to create nodeProcFSM, err:", err)
		return nil, err
	}

	return nodeFsm, err
}

// initStateModel of Heartbeat and initialize the FMS
func initStateModel(p *NodeFSM) (err error) {
	// insert the an node state model here
	stateModel := []fsm.StateModel{
		{ // 对应事件，进入对应状态
			Event:  EventNodeSetup,
			Src:    StateNodeStart,
			Dest:   StateNodeStart,
			CbFunc: NodeSetupCallback,
		},
		{
			Event:  EventNodeSetupAck,
			Src:    StateNodeStart,
			Dest:   StateNodeActive,
			CbFunc: NodeSetupAckCallback,
		},
		{
			Event:  EventNodeVersionNotSupport,
			Src:    StateNodeStart,
			Dest:   StateNodeStart,
			CbFunc: NodeSetupAckCallback,
		},
		{
			Event:  EventNodeUpdate,
			Src:    StateNodeActive,
			Dest:   StateNodeUpdate, //中间状态
			CbFunc: NodeUpdateCallback,
		},
		{
			Event:  EventNodeUpdateAck,
			Src:    StateNodeUpdate,
			Dest:   StateNodeActive,
			CbFunc: NodeUpdateAckCallback,
		},
		{
			Event:  EventNodeRelease,
			Src:    StateNodeActive,
			Dest:   StateNodeRelease, //中间状态
			CbFunc: NodeReleaseCallback,
		},
		{
			Event:  EventNodeReleaseAck,
			Src:    StateNodeRelease,
			Dest:   StateNodeDeactivated,
			CbFunc: NodeReleaseAckCallback,
		},
		{
			Event:  EventNodeTimeout,
			Src:    StateNodeActive,
			Dest:   StateNodeDeactivated,
			CbFunc: NodeTimeoutCallback,
		},
	}

	// add the Event / Source / Destination and CallBack Function into the fsm
	for _, sm := range stateModel {
		err = p.RegisterEvent(sm.Event,
			[]string{sm.Src},
			sm.Dest,
			sm.CbFunc)
		if err != nil {
			return
		}
	}

	return
}

// NodeSetupCallback is callback function
func NodeSetupCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	n := e.Args[0].(*Node)
	fmt.Println(n)

}
func NodeSetupAckCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	n := e.Args[0].(*Node)

	// 进入激活状态
	n.Mu.Lock()
	n.State = pfcpv1.NodeActive
	n.Mu.Unlock()
}

func NodeUpdateCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	n := e.Args[0].(*Node)

	fmt.Println(n)

}
func NodeUpdateAckCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	n := e.Args[0].(*Node)

	fmt.Println(n)

}

func NodeReleaseCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	//get the context from fsm.Event
	ctxt := e.Args[0].(*Node)

	fmt.Println(ctxt)
}
func NodeReleaseAckCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	//get the context from fsm.Event
	n := e.Args[0].(*Node)
	// 处理缓存中的消息
	//ReleaseHandleReceiveScMsgBuff(n)
	// 节点释放时，释放该UPF相关的会话信息
	//ReleaseUPFInfo(n)
	fmt.Println("pfcp node release,", n.NodeID)

	// 进入去激活状态
	n.Mu.Lock()
	n.State = pfcpv1.NodeDeactivated
	n.Mu.Unlock()
	if n.CxtCancel != nil {
		n.CxtCancel() //释放节点
	}

	err := DeleteNode(n.PeerAddr.IP.String())
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Node timeout error %s", err)
	}
	// 关闭重传
	if n.NTimer.T1RetransCancel != nil {
		n.NTimer.T1RetransCancel()
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "T1Retrans release success")
	}
	// 关闭心跳
	if n.NTimer.T1Cancel != nil {
		n.NTimer.T1Cancel() //心跳清理
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "T1Cancel release success")
	}

}

func NodeTimeoutCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	//get the context from fsm.Event
	n := e.Args[0].(*Node)
	// 处理缓存中的消息
	//ReleaseHandleReceiveScMsgBuff(n)
	// 节点释放时，释放该UPF相关的会话信息
	//ReleaseUPFInfo(n)
	fmt.Println("pfcp node release,", n.NodeID)

	// 进入去激活状态
	n.Mu.Lock()
	n.State = pfcpv1.NodeDeactivated
	n.Mu.Unlock()

	// 释放节点
	//n.CxtCancel()
	err := DeleteNode(n.PeerAddr.IP.String())
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Node timeout error %s", err)
	}

	// 清除节点信息
	n.NTimer.T1Cancel() // 心跳goroutine清理
}

// NewNodeProcFSM return a NodeProcFSM pointer after create
// for each sc go route, make sure only one fsm
func NewNodeProcFSM() (*NodeProcFSM, error) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)

	bfsm := fsm.CreateFsm(StateHeartbeatStart)

	nodeFsm := &NodeProcFSM{}
	nodeFsm.Bfsm = bfsm

	err := nodeFsminitStateModel(nodeFsm)
	if err != nil {
		fmt.Println("Failed to create nodeProcFSM, err:", err)
		return nil, err
	}

	return nodeFsm, err
}

// initStateModel of Heartbeat and initialize the FMS
func nodeFsminitStateModel(p *NodeProcFSM) (err error) {
	// insert the an node state model here
	stateModel := []fsm.StateModel{
		{ // 对应事件，进入对应状态
			Event:  EventHeartbeatReqSend,
			Src:    StateHeartbeatStart,
			Dest:   StateHeartbeatReq,
			CbFunc: HeartbeatReqCallback,
		},
		{
			Event:  EventHeartbeatReqRecv,
			Src:    StateHeartbeatStart,
			Dest:   StateHeartbeatReq,
			CbFunc: HeartbeatReqRecvCallback,
		},
		{
			Event:  EventHeartbeatRes,
			Src:    StateHeartbeatReq,
			Dest:   StateHeartbeatRes,
			CbFunc: HeartbeatCmpCallback,
		},
		{
			Event:  EventHeartbeatTimeout,
			Src:    StateHeartbeatReq,
			Dest:   StateHeartbeatRes,
			CbFunc: HeartbeatErrCallback,
		},
	}

	// add the Event / Source / Destination and CallBack Function into the fsm
	for _, sm := range stateModel {
		err = p.RegisterEvent(sm.Event,
			[]string{sm.Src},
			sm.Dest,
			sm.CbFunc)
		if err != nil {
			return
		}
	}

	return
}

// UeCtxtRelReqCallback is callback function
func HeartbeatReqCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	ctxt := e.Args[0].(*pfcpv1.Node)
	fmt.Println(ctxt)

	//	发送请求后，等待响应
	ctxt.HeartbeatResponse = false

}

// 7.4.2.2	Heartbeat Response
func HeartbeatResponseCreate1(req *pfcp.HeartbeatRequest) *pfcpv1.Message {
	//rlogger.FuncEntry(types.ModuleSmfN4, nil)
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

	rlogger.Trace(types.ModuleSmfN4, rlogger.TRACE, nil, msg.String())

	return msg
}

// 收到心跳请求处理
func HeartbeatReqRecvCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	if len(e.Args) != 2 {
		rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, nil,
			"wrong number of parameters")
		return
	}
	n, ok := e.Args[0].(*pfcpv1.Node)
	if !ok {
		rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, nil,
			"Wrong parameter type")
		return
	}
	req, ok := e.Args[1].(*pfcp.HeartbeatRequest)
	if !ok {
		rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, nil,
			"Wrong parameter type")
		return
	}
	// 发送响应消息
	msg := HeartbeatResponseCreate1(req)
	// 编码消息
	data, err := msg.Marshal()
	if err != nil {

		rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, nil, "Pfcp msg marshal err %s", err)
		return
	}
	// 发送消息到 udp server，使用UDP conn 的双工发送
	// 直接发送
	/*ok = n.Server.SendMsgTo(msgCxt)
	if !ok {
		rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, nil, "Channel full")
	}*/
	err = n.SendUdpMsg(data)
	if err != nil {
		rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, nil, "Channel full")
	}
}

func HeartbeatCmpCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	//get the context from fsm.Event
	ctxt := e.Args[0].(int)

	fmt.Println(ctxt)
}

func HeartbeatErrCallback(e *fsm.Event) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	ctxt := e.Args[0].(int)

	fmt.Println(ctxt)
}

//complete
