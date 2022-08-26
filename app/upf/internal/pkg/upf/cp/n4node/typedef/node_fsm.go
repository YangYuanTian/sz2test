package typedef

import (
	"errors"
	"upf/internal/pkg/cmn/fsm"
)

type NodeFSMs struct {
	NodeFsm   *NodeFSM
	NodeHBFSM *NodeProcFSM
}

type NodeFSM struct {
	fsm.BaseFsm
}

// node 状态机定义
// state types definition
const (
	StateNodeStart       = "Node_Start"
	StateNodeActive      = "Node_Active"
	StateNodeUpdate      = "Node_Update"
	StateNodeRelease     = "Node_Release"
	StateNodeDeactivated = "Node_Deactivated"
)

// Heartbeat state model event definition
const (
	EventNodeSetup             = "node_Setup"
	EventNodeSetupAck          = "node_Setup_Ack"
	EventNodeVersionNotSupport = "node_v_not"
	EventNodeUpdate            = "node_Update"
	EventNodeUpdateAck         = "node_Update_Ack"
	EventNodeRelease           = "node_Release"
	EventNodeReleaseAck        = "node_Release_Ack"
	EventNodeReport            = "node_Report"
	EventNodeReportAck         = "node_Report_Ack"
	EventNodePFD               = "node_PFD"
	EventNodePFDAck            = "node_PFD_Ack"
	EventNodeTimeout           = "node_Timeout"
)

var (
	Err_Invalid_Node_State = errors.New("Invalid Regist Managment State")
)

// complete
// CheckState return error, which check the validation for a state string
func (p *NodeFSM) HeartbeatCheckState(state string) error {
	switch state {
	case StateNodeStart:
	case StateNodeActive:
	case StateNodeUpdate:
	case StateNodeRelease:
	case StateNodeDeactivated:
	default:
		return Err_Invalid_Node_State
	}
	return nil
}
