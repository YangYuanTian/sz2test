package typedef

import (
	"errors"
	"upf/internal/pkg/cmn/fsm"
)

// node 状态机定义
// state types definition
// Heartbeat
const (
	StateHeartbeatStart = "Heartbeat_Start"
	StateHeartbeatReq   = "Heartbeat_request"
	StateHeartbeatRes   = "Heartbeat_response"
)

// Heartbeat state model event definition
const (
	EventHeartbeatReqSend = "node_Heartbeat_requestSend"
	EventHeartbeatReqRecv = "node_Heartbeat_requestReceive"
	EventHeartbeatRes     = "node_Heartbeat_response"
	EventHeartbeatTimeout = "node_Heartbeat_Timeout"
)

var (
	Err_Invalid_SMG_State = errors.New("Invalid Regist Managment State")
)

type NodeProcFSM struct {
	fsm.BaseFsm
}

// RmCheckState return error, which check the validation for a state string
func (p *NodeProcFSM) HeartbeatCheckState(state string) error {
	switch state {
	case StateHeartbeatStart:
	case StateHeartbeatReq:
	case StateHeartbeatRes:
	default:
		return Err_Invalid_SMG_State
	}
	return nil
}
