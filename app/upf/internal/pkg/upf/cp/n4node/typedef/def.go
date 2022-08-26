package typedef

import (
	pfcpv1 "upf/internal/pkg/cmn/message/pfcp/v1"
)

// node management
//var NodePool map[string]*Node

type Node struct {
	// 节点数据
	*pfcpv1.Node
	// 节点状态机
	NFsm *NodeFSMs
	// 节点消息状态机
	//updataMsgFsm
	// 节点定时器
	NTimer pfcpv1.NodeTimer
}
