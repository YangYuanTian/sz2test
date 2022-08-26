/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/3/17 13:59
* Description:
 */
package n4node

import (
	"context"
	"fmt"
	"net"
	"time"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/message/pfcp/pfcpudp"
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
	"upf/internal/pkg/cmn/redisclt"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types"
	"upf/internal/pkg/cmn/types3gpp"
	"upf/internal/pkg/openapi/models"
	"upf/internal/pkg/upf/context/pfcpgnbcontext"
	"upf/internal/pkg/upf/cp/n4layer"
	. "upf/internal/pkg/upf/cp/n4node/typedef"
	"upf/internal/pkg/upf/metrics"
)

func SetNodeEvent(event string, n *Node) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//设置node的当前状态
	err := n.NFsm.NodeFsm.Bfsm.Event(event, n)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
			"the node setting event failed(%s),err:%s", n.NFsm.NodeFsm.String(), err)
		return err
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil,
		"the node event (%s)", n.NFsm.NodeFsm.String())
	return nil
}

// 创建新节点
func CreateNode(name *net.UDPAddr) (n *Node, err error) {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	cxt := context.Background()
	nodeData, err := pfcpv1.CreateNode(cxt, name)
	if err != nil {
		return nil, err
	}
	nfsm, err := NewNodeFSM()
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Failed to create nodeProcFSM, err:%s", err)
	}
	nfsmHB, err := NewNodeProcFSM()
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Failed to create nodeProcFSM, err:%s", err)
	}
	n = &Node{Node: nodeData,
		NFsm: &NodeFSMs{NodeFsm: nfsm, NodeHBFSM: nfsmHB}}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "Start creating node:%s", n.NodeID)

	// 设置节点的udp server
	n.Server = pfcpudp.PfcpServer
	n.GtpServer = pfcpudp.GtpServer

	err = AddNode(name.IP.String(), n)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "add node(%s), err:%s ", name.IP, err)
		return nil, err
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "add node success(%s)", name.IP)

	return n, nil
}

func GetNodeApi(key string) (n *Node, err error) {
	return GetNode(key)
}
func GetAllNodeApi() (n []*Node, err error) {
	return ValuesOfNodeTbl()
}

// 创建节点
func HandleAssociationSetupRequest(peerIp *net.UDPAddr, msg *pfcp.PFCPAssociationSetupRequest) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	// 节点检查
	if msg == nil || msg.IE == nil || peerIp == nil {
		return fmt.Errorf("The input parameter is a null pointer")
	}
	if msg.IE.NodeID == nil {
		return fmt.Errorf("The input parameter is a null pointer")
	}
	// 以对端IP作为node的key
	_, err := GetNode(peerIp.IP.String())
	if err == nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
			"The corresponding processing node exist(%s)", peerIp)
		return nil
	}

	// 创建新节点
	n, err := CreateNode(peerIp)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
			"the node creation failed(%s),err:%s", peerIp, err)
		return err
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil,
		"the node creation success(%v)", n.NodeID)

	// 启动心跳检测
	go HeartbeatSetup(n)

	return nil
}

func CreatePFCPAssociationSetupResponse(msg *pfcp.PFCPAssociationSetupRequest) *pfcpv1.Message {
	// 发送响应
	response := &pfcp.PFCPAssociationSetupResponse{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Association_Setup_Response,
			Length:         0, // todo 编码后填充
			SequenceNumber: msg.PfcpHeader.SequenceNumber},
	}
	response.IE = &pfcp.IEPFCPAssociationSetupResponse{}
	if net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4() == nil {
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 5,
			},
			NodeIDType:  pfcp.NodeIDType_IPv6_address,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To16(), //[]byte{10, 202, 94, 1}, N4口ip
		}
	} else {
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 5,
			},
			NodeIDType:  pfcp.NodeIDType_IPv4_address,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4(), //[]byte{10, 202, 94, 1}, N4口ip
		}
	}
	response.IE.Cause = &pfcp.IECause{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeCause,
			Length: 1,
		},
		CauseValue: 1,
	}
	response.IE.UPFunctionFeatures = &pfcp.IEUPFunctionFeatures{}
	err := response.IE.UPFunctionFeatures.Set(pfcp.DDND + pfcp.EMPU + pfcp.PFDM)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp up function features set err %s", err)
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "pfcp up function features set successfully")
	response.IE.IeFlags.Set(pfcp.IeTypeUPFunctionFeatures)

	response.IE.RecoveryTimeStamp = &pfcp.IERecoveryTimeStamp{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeRecoveryTimeStamp,
			Length: 4,
		},
		RecoveryTimeStamp: time.Unix(time.Now().Unix(), 0), //time.Unix(1556588833, 0),
	}
	// optional IE
	response.IE.IeFlags.Set(pfcp.IeTypeUserPlaneIPResourceInformation)
	upResource := &pfcp.IEUserPlaneIPResourceInformation{}
	upResource.V4 = true
	upResource.V6 = true
	upResource.TEIDRI = 4
	upResource.ASSONI = true
	upResource.TEIDRange = 1                                               // 对应1个amf node
	upResource.IPv4address = net.ParseIP(n4layer.UpfN4Layer.N3Ip).To4()    // n3 ip
	upResource.IPv6address = net.ParseIP(n4layer.UpfN4Layer.N3Ipv6).To16() // n3 ipv6
	upResource.NetworkInstance = string(types3gpp.EncodeLables([]byte("n3")))
	response.IE.UserPlaneIPResourceInformation = append(response.IE.UserPlaneIPResourceInformation, upResource)
	////N9
	////if isI-UPF is true , the N9 is equal to the N6
	////if isPAS-UPF is true , the N9 is equal to the N3
	//upResource1 := &pfcp.IEUserPlaneIPResourceInformation{}
	//upResource1.V4 = true
	//upResource1.V6 = true
	//upResource1.TEIDRI = 4
	//upResource1.ASSONI = true
	//upResource1.TEIDRange = 1                                            // 对应1个amf node
	//if configure.UpfConf.IsIUpf{
	//	upResource1.IPv4address = net.ParseIP(configure.UpfConf.N6.Ipv4).To4() // n9 ip
	//	upResource1.IPv6address = net.ParseIP(configure.UpfConf.N6.Ipv6).To16() // n9 ipv6
	//}
	//if configure.UpfConf.IsPasUpf{
	//	upResource1.IPv4address = net.ParseIP(n4layer.UpfN4Layer.N3Ip).To4() // n3 ip
	//	upResource1.IPv6address = net.ParseIP(n4layer.UpfN4Layer.N3Ipv6).To16() // n3 ipv6
	//}
	//upResource1.NetworkInstance = string(types3gpp.EncodeLables([]byte("n9")))
	//response.IE.UserPlaneIPResourceInformation = append(response.IE.UserPlaneIPResourceInformation, upResource1)
	// 构造待编码消息
	// Encoding message filling
	resMsg := &pfcpv1.Message{}
	err = resMsg.HeaderSet(response.PfcpHeader)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "header set:%s", err)
		return nil
	}

	err = resMsg.BodySet(response)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "body set:%s", err)
		return nil
	}

	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, resMsg.String())
	return resMsg
}

func SendResponseMsg(peerIp *net.UDPAddr, res *pfcpv1.Message, event string) error {
	n, err := GetNodeApi(peerIp.IP.String())
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
			"The corresponding processing node does not exist(%s),err:%s", peerIp, err)
		return err
	}
	// 编码消息
	data, err := res.Marshal()
	if err != nil {
		return fmt.Errorf("Pfcp msg marshal err %s", err)
	}
	// 发送消息到 udp server
	err = n.SendUdpMsg(data)
	if err != nil {
		return err
	}
	err = SetNodeEvent(event, n)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
			"the node setting status failed(%s),err:%s", EventNodeSetup, err)
		return err
	}

	return nil
}

func HandleAssociationReleaseRequest(n *Node, msg *pfcp.PFCPAssociationReleaseRequest) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	if n == nil || msg == nil {
		return fmt.Errorf("Illegal message")
	}

	//if n.NTimer.T1RetransCancel != nil {
	//	n.NTimer.T1RetransCancel()
	//}

	// 重置心跳定时器
	n.NTimer.T1Reset()
	// 设置node的当前状态
	//err := n.NFsm.NodeFsm.Bfsm.Event(EventNodeRelease, n)
	//if err != nil {
	//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Setting Status error %s", err)
	//}
	n.NFsm.NodeFsm.Bfsm.SetState(StateNodeRelease)
	// 设置node的当前状态
	err := n.NFsm.NodeFsm.Bfsm.Event(EventNodeReleaseAck, n)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Setting Status error %s", err)
	}
	return nil
}

// 更新节点特性值
func HandleAssociationUpdateRequest(n *Node, msg *pfcp.PFCPAssociationUpdateRequest) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	if n == nil || msg == nil ||
		msg.IE == nil {
		return fmt.Errorf("Illegal message")
	}
	if msg.IE.CPFunctionFeatures != nil {
		switch msg.IE.CPFunctionFeatures.SupportedFeatures {
		case pfcp.LOAD:
			n.CpFeatures.Load = true
		case pfcp.OVRL:
			n.CpFeatures.Ovrl = true
		case pfcp.LOAD + pfcp.OVRL:
			n.CpFeatures.Load = true
			n.CpFeatures.Ovrl = true
		}
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "Update node CP features %+v", n.CpFeatures)
	return nil
}
func CreatePFCPAssociationReleaseResponse(msg *pfcp.PFCPAssociationReleaseRequest) *pfcpv1.Message {
	response := &pfcp.PFCPAssociationReleaseResponse{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Association_Release_Response,
			Length:         0, // todo 编码后填充
			SequenceNumber: msg.PfcpHeader.SequenceNumber},
	}
	response.IE = &pfcp.IEPFCPAssociationReleaseResponse{}
	if net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4() == nil {
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 17,
			},
			NodeIDType:  0,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To16(), //[]byte{10, 202, 94, 2},
		}
	} else {
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 5,
			},
			NodeIDType:  0,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4(), //[]byte{10, 202, 94, 2},
		}
	}
	response.IE.Cause = &pfcp.IECause{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeCause,
			Length: 1,
		},
		CauseValue: 1,
	}
	resMsg := &pfcpv1.Message{}
	resMsg.Header.Length = 0
	err := resMsg.HeaderSet(response.PfcpHeader)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "header set:%s", err)
		return nil
	}
	err = resMsg.BodySet(response)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "body set:%s", err)
		return nil
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "body set:%+v", resMsg.Header)
	return resMsg
}

// 构造节点更新响应消息
func CreatePFCPAssociationUpdateResponse(msg *pfcp.PFCPAssociationUpdateRequest) *pfcpv1.Message {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	// 发送响应
	response := &pfcp.PFCPAssociationUpdateResponse{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Association_Update_Response,
			Length:         0, // todo 编码后填充
			SequenceNumber: msg.PfcpHeader.SequenceNumber},
	}
	response.IE = &pfcp.IEPFCPAssociationUpdateResponse{}
	if net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4() == nil {
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 17,
			},
			NodeIDType:  pfcp.NodeIDType_IPv6_address,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To16(), //[]byte{10, 202, 94, 1},
		}
	} else {
		response.IE.NodeID = &pfcp.IENodeID{
			IETypeLength: pfcp.IETypeLength{
				Type:   pfcp.IeTypeNodeID,
				Length: 5,
			},
			NodeIDType:  pfcp.NodeIDType_IPv4_address,
			NodeIDvalue: net.ParseIP(n4layer.UpfN4Layer.UpfIp).To4(), //[]byte{10, 202, 94, 1},
		}
	}
	response.IE.Cause = &pfcp.IECause{
		IETypeLength: pfcp.IETypeLength{
			Type:   pfcp.IeTypeCause,
			Length: 1,
		},
		CauseValue: pfcp.Cause_Request_accepted,
	}

	// optional IE
	//response.IE.PDRIeFlags.Set(pfcp.IeTypeUserPlaneIPResourceInformation)

	// 构造待编码消息
	// Encoding message filling
	resMsg := &pfcpv1.Message{}
	err := resMsg.HeaderSet(response.PfcpHeader)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "header set:%s", err)
		return nil
	}

	err = resMsg.BodySet(response)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "body set:%s", err)
		return nil
	}

	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "body set:%+v", resMsg.Header)
	return resMsg
}

// 3GPP TS 23.502 V15.4.0 (2018-12)
// 4.4.3.2	N4 Association Update Procedure
// smf side
// send request:smf --> upf
// Message Type: PFCP Association Update Request (7)
func SendAssociationUpdateRequest(n *Node) { // f 是非阻塞调用
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	//检查流程的当前状态
	//if StateNodeActive != n.NFsm.NodeFsm.Bfsm.Current() {
	//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil,
	//		"Current status(%s) message is illegal", n.NFsm.NodeFsm.Bfsm.Current())
	//	return
	//}
	// 创建消息
	msg := AssociationUpdateRequestCreate(n)
	// 编码发送
	data, err := msg.Marshal()
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp msg marshal err %s", err)
	}
	// 发送消息到 udp server，使用UDP conn 的双工发送
	err = n.SendUdpMsg(data)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp msg send err %s", err)
		return
	}
	metrics.UpfmoduleSet.PFCPAssociationUpdateRequestTotalSent.Inc(1)
	// 用于响应的匹配
	n.Request = msg
	// 启动响应超时重传
	err = TimeoutRetransmission(n, data)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp msg Timeout retransmission err: %s", err)
	}
	metrics.UpfmoduleSet.PFCPAssociationUpdateRequestTotalSent.Inc(1)
}

// 7.4.4.3	PFCP Association Update Request
func AssociationUpdateRequestCreate(n *Node) *pfcpv1.Message {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	n.SequenceNumber += 1
	msg := &pfcpv1.Message{}
	request := &pfcp.PFCPAssociationUpdateRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Association_Update_Request,
			Length:         0, // 编码后填充
			SequenceNumber: n.SequenceNumber},
	}
	//Mandatory IE
	request.IE = &pfcp.IEPFCPAssociationUpdateRequest{}
	if n.Server.LocalAddr.IP.To4() != nil {
		request.IE.NodeID = &pfcp.IENodeID{
			NodeIDType:  pfcp.NodeIDType_IPv4_address,
			NodeIDvalue: n.Server.LocalAddr.IP.To4(), // upf ip
		}
	} else {
		request.IE.NodeID = &pfcp.IENodeID{
			NodeIDType:  pfcp.NodeIDType_IPv6_address,
			NodeIDvalue: n.Server.LocalAddr.IP.To16(), // upf ip
		}
	}

	request.IE.UPFunctionFeatures = &pfcp.IEUPFunctionFeatures{}
	//Downlink Data Notification Delay
	//if n.UpFeatures.Ddnd {
	//	err := request.IE.UPFunctionFeatures.Set(pfcp.DDND + pfcp.EMPU)
	//	if err != nil {
	//		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp up function features set err %s", err)
	//	}
	//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "pfcp up function features set successfully")
	//}
	//if n.UpFeatures.Ftup {
	//	err := request.IE.UPFunctionFeatures.Set(pfcp.FTUP)
	//	if err != nil {
	//		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp up function features set err %s", err)
	//	}
	//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "pfcp up function features set successfully")
	//}
	{
		supFeatures := uint16(0)
		supFeatures += pfcp.Charge(n.UpFeatures.Bucp, pfcp.BUCP)
		supFeatures += pfcp.Charge(n.UpFeatures.Ddnd, pfcp.DDND)
		supFeatures += pfcp.Charge(n.UpFeatures.Dlbd, pfcp.DLBD)
		supFeatures += pfcp.Charge(n.UpFeatures.Trst, pfcp.TRST)
		supFeatures += pfcp.Charge(n.UpFeatures.Ftup, pfcp.FTUP)
		supFeatures += pfcp.Charge(n.UpFeatures.Pfdm, pfcp.PFDM)
		supFeatures += pfcp.Charge(n.UpFeatures.Heeu, pfcp.HEEU)
		supFeatures += pfcp.Charge(n.UpFeatures.Treu, pfcp.TREU)
		supFeatures += pfcp.Charge(n.UpFeatures.Empu, pfcp.EMPU)
		supFeatures += pfcp.Charge(n.UpFeatures.Pdiu, pfcp.PDIU)
		supFeatures += pfcp.Charge(n.UpFeatures.Udbc, pfcp.UDBC)
		supFeatures += pfcp.Charge(n.UpFeatures.Quoac, pfcp.QUOAC)
		supFeatures += pfcp.Charge(n.UpFeatures.Trace, pfcp.TRACE)
		supFeatures += pfcp.Charge(n.UpFeatures.Frrt, pfcp.FRRT)
		supFeatures += pfcp.Charge(n.UpFeatures.Pfde, pfcp.PFDE)
		request.IE.UPFunctionFeatures.Set(supFeatures)
	}
	request.IE.IeFlags.Set(pfcp.IeTypeUPFunctionFeatures)

	//PFCPAssociationReleaseRequest
	if n.SARR {
		request.IE.PFCPAssociationReleaseRequest = &pfcp.IEPFCPAssociationReleaseRequest{}
		request.IE.PFCPAssociationReleaseRequest.Set(0)
		request.IE.PFCPAssociationReleaseRequest.SARR = true
		request.IE.IeFlags.Set(pfcp.IeTypeIEPFCPAssociationReleaseRequest)
	}
	// 构造待编码消息
	// Encoding message filling
	err := msg.HeaderSet(request.PfcpHeader)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp header set err %s", err)
	}
	err = msg.BodySet(request)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp body set err %s", err)
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, msg.String())

	return msg
}

// 更新节点特性值
func HandleAssociationUpdateResponse(n *Node, msg *pfcp.PFCPAssociationUpdateResponse) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	// 关闭请求重传
	if n.NTimer.T2Cancel != nil {
		n.NTimer.T2Cancel()
	}
	if n == nil || msg == nil ||
		msg.IE == nil {
		return fmt.Errorf("Illegal message")
	}
	if msg.IE.Cause == nil {
		return fmt.Errorf("Illegal message, mandatory IE incorrect")
	}
	if msg.IE.Cause.CauseValue != pfcp.Cause_Request_accepted {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "Update node UP features Not successful(%v)", msg.IE.Cause.CauseValue)
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "Node features updated successfully")
	return nil
}

// 发送 node report request
func SendNodeReportRequest(info *pfcpgnbcontext.PfcpGnbInfo) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	// 获取节点信息
	n, err := GetNodeApi(info.PfcpNodeId)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil,
			"The corresponding processing node does not exist(%s),err:%s", info.PfcpNodeId, err)
		return err
	}
	//	创建节点报告
	//7.4.5.1	PFCP Node Report Request
	msg := NodeReportRequestCreate(n, info)
	// 编码发送
	data, err := msg.Marshal()
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp msg marshal err %s", err)
	}
	// 发送消息到 udp server，使用UDP conn 的双工发送
	err = n.SendUdpMsg(data)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp msg send err %s", err)
		return err
	}

	//// 启动响应超时重传
	//err = TimeoutRetransmission(n, data)
	//if err != nil {
	//	rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp msg Timeout retransmission err: %s", err)
	//}
	return nil
}

// 7.4.5.1	PFCP Node Report Request
func NodeReportRequestCreate(n *Node, info *pfcpgnbcontext.PfcpGnbInfo) *pfcpv1.Message {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)
	n.SequenceNumber += 1
	msg := &pfcpv1.Message{}
	request := &pfcp.PFCPNodeReportRequest{
		PfcpHeader: pfcp.PfcpHeaderforNode{
			Version:        pfcp.Version,
			MessageType:    pfcp.PFCP_Node_Report_Request,
			Length:         0, // 编码后填充
			SequenceNumber: n.SequenceNumber},
	}
	//Mandatory IE
	request.IE = &pfcp.IEPFCPNodeReportRequest{}
	if n.Server.LocalAddr.IP.To4() != nil {
		request.IE.NodeID = &pfcp.IENodeID{
			NodeIDType:  pfcp.NodeIDType_IPv4_address,
			NodeIDvalue: n.Server.LocalAddr.IP.To4(), // upf ip
		}
	} else {
		request.IE.NodeID = &pfcp.IENodeID{
			NodeIDType:  pfcp.NodeIDType_IPv6_address,
			NodeIDvalue: n.Server.LocalAddr.IP.To16(), // upf ip
		}
	}

	request.IE.NodeReportType = &pfcp.IENodeReportType{
		UPFR: true,
	}
	if net.ParseIP(info.GnbNodeId).To4() != nil {
		request.IE.UserPlanePathFailureReport = &pfcp.IEUserPlanePathFailureReport{
			RemoteGTPUPeer: &pfcp.IERemoteGTPUPeer{
				V4:          true,
				IPv4address: net.ParseIP(info.GnbNodeId),
			},
		}
	} else {
		request.IE.UserPlanePathFailureReport = &pfcp.IEUserPlanePathFailureReport{
			RemoteGTPUPeer: &pfcp.IERemoteGTPUPeer{
				V6:          true,
				IPv6address: net.ParseIP(info.GnbNodeId),
			},
		}
	}
	request.IE.IeFlags.Set(pfcp.IeTypeUserPlanePathFailureReport)

	// 构造待编码消息
	// Encoding message filling
	err := msg.HeaderSet(request.PfcpHeader)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp header set err %s", err)
	}
	err = msg.BodySet(request)
	if err != nil {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "pfcp body set err %s", err)
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, msg.String())

	return msg
}

func HandleNodeReportResponse(n *Node, msg *pfcp.PFCPNodeReportResponse) error {
	rlogger.FuncEntry(types.ModuleUpfN4Node, nil)

	if n == nil || msg == nil ||
		msg.IE == nil {
		return fmt.Errorf("Illegal message")
	}
	if msg.IE.Cause == nil {
		return fmt.Errorf("Illegal message, mandatory IE incorrect")
	}
	if msg.IE.Cause.CauseValue != pfcp.Cause_Request_accepted {
		rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "Node report request not successful(%v)", msg.IE.Cause.CauseValue)
	}
	rlogger.Trace(types.ModuleUpfN4Node, rlogger.INFO, nil, "Node report request successful")
	return nil
}

func HandlePfcpPFDManagementRequest(msg *pfcp.PFCPPFDManagementRequest) (err error) {
	for _, ApplicationIDsPFDs := range msg.IE.ApplicationIDsPFDs {
		appId := string(ApplicationIDsPFDs.ApplicationID.ApplicationIdentifier)
		pfdcontents := ApplicationIDsPFDs.PFD
		var pfdDataForApp models.PfdDataForAppExt
		pfdDataForApp.Pfds = make([]models.PfdContent, len(pfdcontents))
		pfdDataForApp.ApplicationId = appId
		fmt.Printf("msg = %#v\n", *msg)
		fmt.Println("appId = ", appId)
		fmt.Println("pfdcontents = ", pfdcontents)
		if pfdcontents == nil {
			_, err = redisclt.Agent.HDel("upf_pfd_data", appId)
			if err != nil {
				fmt.Println("===============HandlePfcpPFDManagementRequest=================1==========")
				rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "redis del appId-pfdDataForApp failed: %s", err)
			}
			return nil
		}

		for k, v := range pfdcontents {
			pfdDataForApp.Pfds[k].PfdId = appId + "-" + string(k)
			pfdDataForApp.Pfds[k].FlowDescription = v.PFDContexts.FlowDescription
			pfdDataForApp.Pfds[k].Url = v.PFDContexts.URL
			pfdDataForApp.Pfds[k].DomainName = v.PFDContexts.DomainName
			pfdDataForApp.Pfds[k].DnProtocol = v.PFDContexts.DomainNameProtocol
		}

		fmt.Println("appId-1 = ", appId)
		_, err = redisclt.Agent.HSet("upf_pfd_data", appId, pfdDataForApp)
		if err != nil {
			rlogger.Trace(types.ModuleUpfN4Node, rlogger.WARN, nil, "store appId-pfdDataForApp to redis failed")
			return err
		}
	}
	return nil
}
