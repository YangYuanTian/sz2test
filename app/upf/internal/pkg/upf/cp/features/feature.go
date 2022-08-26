/*
* Copyright(C),2020‐2022
* Author: Lenovo
* Date: 2021/3/25 14:10
* Description:
 */
package features

import (
	"fmt"
	pfcpv1 "lite5gc/cmn/message/pfcp/v1"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/clitypes"
	"lite5gc/upf/cp/n4node"
	"lite5gc/upf/stateless/recoverdata"
	"time"
)

// main--> features--> n4udp
var upFeatures pfcpv1.UpFeatures

type NodesInfo struct {
	Tips  string
	Nodes []NodeInfo `json:"node list"`
}
type NodeInfo struct {
	NodeID string `json:"node id"`
}

func init() {
	upFeatures.Ddnd = true
	upFeatures.Empu = true
}

// Downlink Data Notification Delay,API
func DLDataNotificationDelayModify(onOff bool) interface{} {
	time.Sleep(time.Second)
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	var hint clitypes.TipsInfo
	var nodes NodesInfo
	// 获得UPF节点列表
	nodeList, err := n4node.GetAllNodeApi()
	if err != nil || len(nodeList) == 0 {
		hint.Tips = fmt.Sprint("there are no nodes")
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
		nodes.Tips = hint.Tips
		return nodes
	}
	//在获取当前UPF UP feature DDND的状态
	if upFeatures.Ddnd == onOff { //表明状态没有发生改变
		hint.Tips = fmt.Sprintf("the state has not changed (%v)", onOff)
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
		return hint
	}
	upFeatures.Ddnd = onOff //状态修改成功
	// UPF 触发 PFCP Association Update Request
	var numNode int
	for _, node := range nodeList {
		node.UpFeatures = upFeatures
		n4node.SendAssociationUpdateRequest(node)
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, node.NodeID)
		numNode += 1
		nodes.Nodes = append(nodes.Nodes, NodeInfo{node.NodeID})
	}
	hint.Tips = fmt.Sprintf("the state has changed (%v),"+
		"the number of nodes is (%v)", onOff, numNode)
	rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
	nodes.Tips = hint.Tips
	return nodes
}
func HEEU(onOff bool) interface{} {
	return nil
}
func LOAD(onOff bool) interface{} {
	return nil
}
func FTUP(onOff bool) interface{} {
	time.Sleep(time.Second)
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	var hint clitypes.TipsInfo
	var nodes NodesInfo

	// 获得UPF节点列表
	nodeList, err := n4node.GetAllNodeApi()
	if err != nil || len(nodeList) == 0 {
		hint.Tips = fmt.Sprint("there are no nodes.")
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
		nodes.Tips = hint.Tips
		return nodes
	}
	//在获取当前UPF UP feature FTUP的状态
	if upFeatures.Ftup == onOff { //表明状态没有发生改变
		if upFeatures.Ftup == false {
			hint.Tips = fmt.Sprintf("the state has not changed , The switch for assigning TEID to UPF is OFF.")
		} else {
			hint.Tips = fmt.Sprintf("the state has not changed , The switch for assigning TEID to UPF is ON.")
		}
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
		nodes.Tips = hint.Tips
		return nodes
	}
	// UPF 触发 PFCP Association Update Request
	var numNode int
	upFeatures.Ftup = onOff //状态修改成功
	for _, node := range nodeList {
		node.UpFeatures = upFeatures
		n4node.SendAssociationUpdateRequest(node)
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, node.NodeID)
		numNode += 1
		nodes.Nodes = append(nodes.Nodes, NodeInfo{node.NodeID})
	}
	if onOff == false {
		hint.Tips = fmt.Sprintf("the state has changed (%v),"+
			"The switch for assigning TEID to UPF is OFF,"+"the number of nodes is (%v).", onOff, numNode)
	} else {
		hint.Tips = fmt.Sprintf("the state has changed (%v),"+
			"The switch for assigning TEID to UPF is ON,"+"the number of nodes is (%v).", onOff, numNode)
	}
	rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
	nodes.Tips = hint.Tips
	return nodes
}
func UPFSUSPENDED(onOff bool) interface{} {
	recoverdata.UpfCxt.ControlSUSP()
	return nil
}
func OFFLINE(onOff bool) interface{} {
	time.Sleep(time.Second)
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	var hint clitypes.TipsInfo
	var nodes NodesInfo

	// 获得UPF节点列表
	nodeList, err := n4node.GetAllNodeApi()
	if err != nil || len(nodeList) == 0 {
		hint.Tips = fmt.Sprint("there are no nodes.")
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
		nodes.Tips = hint.Tips
		return nodes
	}
	if !onOff {
		hint.Tips = fmt.Sprint("false UPF not change,UPF offline need set to True.")
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, hint.Tips)
		nodes.Tips = hint.Tips
		return nodes
	}
	// UPF 触发 PFCP Association Update Request
	var numNode int
	for _, node := range nodeList {
		node.SARR = onOff
		n4node.SendAssociationUpdateRequest(node)
		rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, node.NodeID)
		numNode += 1
		nodes.Nodes = append(nodes.Nodes, NodeInfo{node.NodeID})
	}
	rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, "node number is %d", numNode)
	rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, "UPF online successfully", hint.Tips)
	hint.Tips = fmt.Sprintf("UPF SARR is (%v) Notify all SMFS UPF is offline, the number of nodes is (%v).", onOff, numNode)
	nodes.Tips = hint.Tips
	clearUPFeature()
	rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, nil, "UPF offline all feature are clear,also retain DDND and EMPU ")
	return nodes
}
func clearUPFeature() {
	upFeatures.Ddnd = false
	upFeatures.Bucp = false
	upFeatures.Ddnd = true
	upFeatures.Dlbd = false
	upFeatures.Trst = false
	upFeatures.Ftup = false
	upFeatures.Pfdm = false
	upFeatures.Heeu = false
	upFeatures.Treu = false
	upFeatures.Empu = true
	upFeatures.Pdiu = false
	upFeatures.Udbc = false
	upFeatures.Quoac = false
	upFeatures.Trace = false
	upFeatures.Frrt = false
	upFeatures.Pfde = false
}
