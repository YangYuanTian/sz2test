package n4udp

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"upf/internal/pkg/cmn/message/pfcp"
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types"
	"upf/internal/pkg/cmn/utils"
	"upf/internal/pkg/upf/context/n4context"
	"upf/internal/pkg/upf/context/pfcpgnbcontext"
	"upf/internal/pkg/upf/cp/features"
	"upf/internal/pkg/upf/cp/n4layer"
	"upf/internal/pkg/upf/cp/n4node"
	. "upf/internal/pkg/upf/cp/n4node/typedef"
	"upf/internal/pkg/upf/metrics"
	"upf/internal/pkg/upf/stateless/recoverdata"
)

func printStackTrace(name string) string {
	var index int
	for i := 1; ; i++ {
		pc, _, _, _ := runtime.Caller(i)
		funcName := runtime.FuncForPC(pc).Name()
		if funcName == name {
			index = i - 1
			break
		}
	}
	buf := new(bytes.Buffer)
	pc, _, _, _ := runtime.Caller(index)
	funcName := runtime.FuncForPC(pc).Name()
	fmt.Fprintf(buf, "%s", funcName)
	return buf.String()
}
func Dispatch(peerIp *net.UDPAddr, msg pfcpv1.Message, res *pfcpv1.Message) error {
	defer func() {
		//n, _ := n4node.GetNodeApi(peerIp.IP.String())
		if err := recover(); err != nil {
			//fmt.Println(printStackTrace())
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "%s", debug.Stack())
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
				"Dispatch happen panic:%+v", err)
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
				"Dispatch happen panic:%+v", string(debug.Stack()))
			//e := printStackTrace("main.Dispatch")
			//
			////fmt.Println(e)
			//if e == "main.CreatePFCPAssociationSetupResponse"||e=="main.SendResponseMsg" {
			//	if n!=nil{
			//		//n.NTimer.T1Reset()
			//		//// 设置node的当前状态
			//		//err := n.NFsm.NodeFsm.Bfsm.Event(EventNodeRelease, n)
			//		//if err != nil {
			//		//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Setting Status error %s", err)
			//		//}
			//		//// 设置node的当前状态
			//		err = n.NFsm.NodeFsm.Bfsm.Event(EventNodeReleaseAck, n)
			//		if err != nil {
			//			rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Setting Status error %s", err)
			//		}
			//	}
			//}else if e=="main.CreatePFCPAssociationUpdateResponse"{
			//		request, ok := msg.Body.(*pfcp.PFCPAssociationUpdateRequest)
			//		if ok!=false &&  n != nil &&  request.IE.CPFunctionFeatures != nil{
			//			switch request.IE.CPFunctionFeatures.SupportedFeatures {
			//			case pfcp.LOAD:
			//				n.CpFeatures.Load = false
			//			case pfcp.OVRL:
			//				n.CpFeatures.Ovrl = false
			//			case pfcp.LOAD + pfcp.OVRL:
			//				n.CpFeatures.Load = false
			//				n.CpFeatures.Ovrl = false
			//		}
			//		}
			//	}else if e=="main.CreatePFCPAssociationReleaseResponse"{
			//		if n!=nil{
			//			//n.NTimer.T1Reset()
			//			//// 设置node的当前状态
			//			//
			//			//err := n.NFsm.NodeFsm.Bfsm.Event(EventNodeSetup , n)
			//			//if err != nil {
			//			//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Setting Status error %s", err)
			//			//}
			//			//// 设置node的当前状态
			//			//err = n.NFsm.NodeFsm.Bfsm.Event(EventNodeSetupAck, n)
			//			//if err != nil {
			//			//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Setting Status error %s", err)
			//			//}
			//			_, err = n4node.CreateNode(peerIp)
			//			if err != nil {
			//				rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
			//					"the node creation failed(%s),err:%s", peerIp, err)
			//			}
			//
			//		}
			//	}else if e=="main.SessionEstablishmentRequest"{
			//		request, ok := msg.Body.(*pfcp.SessionEstablishmentRequest)
			//		if ok{
			//			upfCxt := n4layer.StoreUpfN4Context(*request)
			//			n4layer.ExceptionSessionRelease(upfCxt)
			//		}
			//
			//	}
		}
	}()
	switch msg.Header.MessageType {
	case pfcp.PFCP_Heartbeat_Request:
		_, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		request, ok := msg.Body.(*pfcp.HeartbeatRequest)
		if !ok {
			return fmt.Errorf("type error")
		}

		err = msg.HeaderFillToMsg(&request.PfcpHeader)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		metrics.UpfmoduleSet.HeartBeatRequestTotalReceived.Inc(1)
		response := &pfcp.HeartbeatResponse{}
		if ok {
			err := pfcpv1.HandlePfcpHeartbeatRequest(*request, response)
			if err != nil {
				return err
			}
			pfcpHeader := pfcp.PfcpHeader{}
			pfcpHeader.Version = response.PfcpHeader.Version
			pfcpHeader.MessageType = response.PfcpHeader.MessageType
			pfcpHeader.Length = response.PfcpHeader.Length
			pfcpHeader.SequenceNumber = response.PfcpHeader.SequenceNumber

			res.Header = pfcpHeader
			res.Body = response
			return nil
		}
		metrics.UpfmoduleSet.HeartBeatResponseTotalSent.Inc(1)
	case pfcp.PFCP_Heartbeat_Response:
		n, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		request, ok := msg.Body.(*pfcp.HeartbeatResponse)
		if !ok {
			return fmt.Errorf("type error")
		}
		err = msg.HeaderFillToMsg(&request.PfcpHeader)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		err = n4node.HandleHeartbeatResponse(n, request)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		metrics.UpfmoduleSet.HeartBeatResponseTotalReceived.Inc(1)
		return nil

	case pfcp.PFCP_PFD_Management_Request:
		request, ok := msg.Body.(*pfcp.PFCPPFDManagementRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		request.PfcpHeader.Version = msg.Header.Version
		request.PfcpHeader.MessageType = msg.Header.MessageType
		request.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber

		err := n4node.HandlePfcpPFDManagementRequest(request)
		if err != nil {
			return err
		}
		metrics.UpfmoduleSet.PFCPPFDManagementRequestTotalReceived.Inc(1)
		response := &pfcp.PFCPPFDManagementResponse{}
		response.IE = &pfcp.IEPFCPPFDManagementResponse{
			Cause: &pfcp.IECause{
				CauseValue: pfcp.Cause_Request_accepted,
			},
		}

		pfcpHeader := pfcp.PfcpHeader{}
		pfcpHeader.Version = pfcp.Version
		pfcpHeader.MessageType = pfcp.PFCP_PFD_Management_Response
		pfcpHeader.Length = 0
		pfcpHeader.SequenceNumber = request.PfcpHeader.SequenceNumber

		res.Header = pfcpHeader
		res.Body = response
		metrics.UpfmoduleSet.PFCPPFDManagementResponseTotalSent.Inc(1)
		return nil

		//case pfcp.PfcpPfdManagementResponse:
		//	pfcp_handler.HandlePfcpPfdManagementResponse(msg)
	case pfcp.PFCP_Association_Setup_Request:
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.DEBUG, nil, "response normal")
		request, ok := msg.Body.(*pfcp.PFCPAssociationSetupRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		err := msg.HeaderFillToMsg(&request.PfcpHeader)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		// 处理请求，创建节点，设置状态
		err = n4node.HandleAssociationSetupRequest(peerIp, request)
		if err != nil {
			return err
		}
		metrics.UpfmoduleSet.PFCPAssociationSetupRequestTotalReceived.Inc(1)
		// 构造响应
		res = n4node.CreatePFCPAssociationSetupResponse(request)
		// 发送响应
		err = n4node.SendResponseMsg(peerIp, res, EventNodeSetupAck)
		if err != nil {
			return err
		}
		//todo 触发 UP features 更新
		metrics.UpfmoduleSet.PFCPAssociationSetupResponseTotalSent.Inc(1)
		go features.DLDataNotificationDelayModify(true)
	case pfcp.PFCP_Association_Setup_Response:
		rmsg, ok := msg.Body.(*pfcp.PFCPAssociationSetupResponse)
		if !ok {
			return fmt.Errorf("type error")
		}
		pfcpv1.HandleAssociationSetupResponse(rmsg)
	case pfcp.PFCP_Association_Update_Request:
		n, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		request, ok := msg.Body.(*pfcp.PFCPAssociationUpdateRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		err = msg.HeaderFillToMsg(&request.PfcpHeader)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		// 处理节点更新消息
		err = n4node.HandleAssociationUpdateRequest(n, request)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		metrics.UpfmoduleSet.PFCPAssociationUpdateRequestTotalReceived.Inc(1)
		// 构造响应
		resMsg := n4node.CreatePFCPAssociationUpdateResponse(request)
		// 外部统一发送
		*res = *resMsg
		recoverdata.AddN4NodeToRedis(peerIp.IP.String(), n)
		metrics.UpfmoduleSet.PFCPAssociationUpdateResponseTotalSent.Inc(1)
	case pfcp.PFCP_Association_Update_Response:
		n, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		request, ok := msg.Body.(*pfcp.PFCPAssociationUpdateResponse)
		if !ok {
			return fmt.Errorf("type error")
		}
		err = msg.HeaderFillToMsg(&request.PfcpHeader)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		// 处理节点更新响应
		err = n4node.HandleAssociationUpdateResponse(n, request)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		recoverdata.AddN4NodeToRedis(peerIp.IP.String(), n)
		metrics.UpfmoduleSet.PFCPAssociationUpdateResponseTotalReceived.Inc(1)
	case pfcp.PFCP_Association_Release_Request:
		n, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		request, ok := msg.Body.(*pfcp.PFCPAssociationReleaseRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		// 消息头填充
		err = msg.HeaderFillToMsg(&request.PfcpHeader)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		// 释放处理
		err = n4node.HandleAssociationReleaseRequest(n, request)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		metrics.UpfmoduleSet.PFCPAssociationReleaseRequestTotalReceived.Inc(1)
		resMsg := n4node.CreatePFCPAssociationReleaseResponse(request)
		*res = *resMsg
		//response := &pfcp.PFCPAssociationReleaseResponse{
		//	PfcpHeader: pfcp.PfcpHeaderforNode{
		//		Version:        pfcp.Version,
		//		MessageType:    pfcp.PFCP_Association_Release_Response,
		//		Length:         0, // todo 编码后填充
		//		SequenceNumber: msg.Header.SequenceNumber},
		//}
		//response.IE = &pfcp.IEPFCPAssociationReleaseResponse{}
		//response.IE.NodeID = &pfcp.IENodeID{
		//	IETypeLength: pfcp.IETypeLength{
		//		Type:   pfcp.IeTypeNodeID,
		//		Length: 5,
		//	},
		//	NodeIDType:  0,
		//	NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4(), //[]byte{10, 202, 94, 2},
		//}
		//response.IE.Cause = &pfcp.IECause{
		//	IETypeLength: pfcp.IETypeLength{
		//		Type:   pfcp.IeTypeCause,
		//		Length: 1,
		//	},
		//	CauseValue: 1,
		//}
		//
		//res.Header = msg.Header
		//res.Header.MessageType = response.PfcpHeader.MessageType
		////todo 编码后填充
		//res.Header.Length = 0
		//res.Body = response
		recoverdata.DeleteN4NodeInRedis(peerIp.IP.String(), recoverdata.UpfCxt)
		metrics.UpfmoduleSet.PFCPAssociationReleaseResponseTotalSent.Inc(1)
		//case pfcp.PfcpAssociationReleaseResponse:
		//	pfcp_handler.HandlePfcpAssociationReleaseResponse(msg)
	case pfcp.PFCP_Node_Report_Request:
		msg, ok := msg.Body.(*pfcp.PFCPNodeReportRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		err := pfcpv1.HandleNodeReportRequest(msg)
		if err != nil {
			return err
		}
		metrics.UpfmoduleSet.PFCPNodeReportRequestTotalSent.Inc(1)
	case pfcp.PFCP_Node_Report_Response:
		n, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		request, ok := msg.Body.(*pfcp.PFCPNodeReportResponse)
		if !ok {
			return fmt.Errorf("type error")
		}

		err = msg.HeaderFillToMsg(&request.PfcpHeader)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		// 处理节点报告响应
		err = n4node.HandleNodeReportResponse(n, request)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "err:%s", err)
			return err
		}
		metrics.UpfmoduleSet.PFCPNodeReportResponseTotalReceived.Inc(1)
		//case pfcp.PfcpSessionSetDeletionRequest:
		//	pfcp_handler.HandlePfcpSessionSetDeletionRequest(msg)
		//case pfcp.PfcpSessionSetDeletionResponse:
		//	pfcp_handler.HandlePfcpSessionSetDeletionResponse(msg)
	case pfcp.PFCP_Session_Establishment_Request:
		_, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		var n4 n4layer.N4Msg
		request, ok := msg.Body.(*pfcp.SessionEstablishmentRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		//解码消息头填充处理消息头
		request.PfcpHeader.Version = msg.Header.Version
		request.PfcpHeader.MPFlag = msg.Header.MPFlag
		request.PfcpHeader.SFlag = msg.Header.SFlag

		request.PfcpHeader.MessageType = msg.Header.MessageType
		request.PfcpHeader.Length = msg.Header.Length
		request.PfcpHeader.SEID = msg.Header.SEID
		request.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber
		request.PfcpHeader.MessagePriority = msg.Header.MessagePriority

		response := &pfcp.SessionEstablishmentResponse{}

		err = n4.SessionEstablishmentRequest(*request, response)
		if err != nil {
			return err
		}
		metrics.UpfmoduleSet.PFCPSessionEstablishmentRequestTotalReceived.Inc(1)
		pfcpHeader := pfcp.PfcpHeader{}
		pfcpHeader.Version = response.PfcpHeader.Version
		pfcpHeader.MPFlag = response.PfcpHeader.MPFlag
		pfcpHeader.SFlag = response.PfcpHeader.SFlag

		pfcpHeader.MessageType = response.PfcpHeader.MessageType
		pfcpHeader.Length = response.PfcpHeader.Length
		pfcpHeader.SEID = response.PfcpHeader.SEID
		pfcpHeader.SequenceNumber = response.PfcpHeader.SequenceNumber
		pfcpHeader.MessagePriority = response.PfcpHeader.MessagePriority

		res.Header = pfcpHeader
		res.Body = response
		metrics.UpfmoduleSet.PFCPSessionEstablishmentResponseTotalSent.Inc(1)
		return nil
	case pfcp.PFCP_Session_Modification_Request:
		n, err := n4node.GetNodeApi(peerIp.IP.String())
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
				"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
			return err
		}
		var n4 n4layer.N4Msg
		request, ok := msg.Body.(*pfcp.SessionModifyRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		//解码消息头填充处理消息头
		request.PfcpHeader.Version = msg.Header.Version
		request.PfcpHeader.MPFlag = msg.Header.MPFlag
		request.PfcpHeader.SFlag = msg.Header.SFlag

		request.PfcpHeader.MessageType = msg.Header.MessageType
		request.PfcpHeader.Length = msg.Header.Length
		request.PfcpHeader.SEID = msg.Header.SEID
		request.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber
		request.PfcpHeader.MessagePriority = msg.Header.MessagePriority

		response := &pfcp.SessionModifyResponse{}

		err = n4.SessionModifyRequest(*request, response)
		if err != nil {
			return err
		}
		metrics.UpfmoduleSet.PFCPSessionModificationRequestTotalReceived.Inc(1)
		pfcpHeader := pfcp.PfcpHeader{}
		pfcpHeader.Version = response.PfcpHeader.Version
		pfcpHeader.MPFlag = response.PfcpHeader.MPFlag
		pfcpHeader.SFlag = response.PfcpHeader.SFlag

		pfcpHeader.MessageType = response.PfcpHeader.MessageType
		pfcpHeader.Length = response.PfcpHeader.Length
		pfcpHeader.SEID = response.PfcpHeader.SEID
		pfcpHeader.SequenceNumber = response.PfcpHeader.SequenceNumber
		pfcpHeader.MessagePriority = response.PfcpHeader.MessagePriority

		res.Header = pfcpHeader
		res.Body = response

		// 会话创建成功
		if response.IE.Cause.CauseValue == pfcp.Cause_Request_accepted {
			// ---------------------------------------
			//	保存pfcp节点与gnb关系表
			//	key pfcp node ip + gnb ip
			// ---------------------------------------
			// 读取当前上下文
			n4Cxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(request.PfcpHeader.SEID))
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(request.PfcpHeader.SEID), "Failed to get N4 Context:%s", err)
				return err
			}

			n4Cxt.PfcpNodeId = n.NodeID
			if n4Cxt.PfcpNodeId == "" || n4Cxt.GtpuNodeID == "" {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(n4Cxt.SEID),
					"failed to add pfcpgnb table,Parameter error: PfcpNodeId(%s),GtpuNodeID:(%+v)", n4Cxt.PfcpNodeId, n4Cxt.GtpuNodeID)
			}
			key := n.NodeID + n4Cxt.GtpuNodeID
			value := &pfcpgnbcontext.PfcpGnbInfo{
				n.NodeID,
				n4Cxt.GtpuNodeID}
			//	保存pfcp节点与gnb关系表
			err = pfcpgnbcontext.Add(key, value)
			if err != nil {
				// 重复不添加
				rlogger.Trace(moduleTag, rlogger.DEBUG, utils.Seid(n4Cxt.SEID), "add pfcpgnb table: %s,dst ip:%v", err, key)
			}
			rlogger.Trace(moduleTag, rlogger.DEBUG, utils.Seid(n4Cxt.SEID), "add pfcpgnb table: key(%s),value:(%+v)", key, value)
		}
		metrics.UpfmoduleSet.PFCPSessionModificationResponseTotalSent.Inc(1)
		return nil
		//case pfcp.PfcpSessionModificationResponse:
		//	pfcp_handler.HandlePfcpSessionModificationResponse(msg, ResponseQueue)
	case pfcp.PFCP_Session_Deletion_Request:
		var n4 n4layer.N4Msg
		request, ok := msg.Body.(*pfcp.SessionReleaseRequest)
		if !ok {
			return fmt.Errorf("type error")
		}
		//解码消息头填充处理消息头
		request.PfcpHeader.Version = msg.Header.Version
		request.PfcpHeader.MPFlag = msg.Header.MPFlag
		request.PfcpHeader.SFlag = msg.Header.SFlag

		request.PfcpHeader.MessageType = msg.Header.MessageType
		request.PfcpHeader.Length = msg.Header.Length
		request.PfcpHeader.SEID = msg.Header.SEID
		request.PfcpHeader.SequenceNumber = msg.Header.SequenceNumber
		request.PfcpHeader.MessagePriority = msg.Header.MessagePriority

		response := &pfcp.SessionReleaseResponse{}

		err := n4.SessionReleaseRequest(*request, response)
		if err != nil {
			return err
		}
		metrics.UpfmoduleSet.PFCPSessionDeletionRequestTotalReceived.Inc(1)
		pfcpHeader := pfcp.PfcpHeader{}
		pfcpHeader.Version = response.PfcpHeader.Version
		pfcpHeader.MPFlag = response.PfcpHeader.MPFlag
		pfcpHeader.SFlag = response.PfcpHeader.SFlag

		pfcpHeader.MessageType = response.PfcpHeader.MessageType
		pfcpHeader.Length = response.PfcpHeader.Length
		pfcpHeader.SEID = response.PfcpHeader.SEID
		pfcpHeader.SequenceNumber = response.PfcpHeader.SequenceNumber
		pfcpHeader.MessagePriority = response.PfcpHeader.MessagePriority

		res.Header = pfcpHeader
		res.Body = response
		metrics.UpfmoduleSet.PFCPSessionDeletionResponseTotalSent.Inc(1)
		return nil
	case pfcp.PFCP_Session_Report_Request:
		metrics.UpfmoduleSet.PFCPSessionReportRequestTotalSent.Inc(1)
		return nil
	case pfcp.PFCP_Session_Report_Response:
		rmsg, ok := msg.Body.(*pfcp.SessionReportResponse)
		if !ok {
			return fmt.Errorf("type error")
		}
		err := n4layer.SessionReportResponseHandle(rmsg)
		if err != nil {
			return err
		}
		metrics.UpfmoduleSet.PFCPSessionReportResponseTotalReceived.Inc(1)
		return nil

	default:
		return fmt.Errorf("Unknown PFCP message type: %d", msg.Header.MessageType)

	}
	return nil

}
