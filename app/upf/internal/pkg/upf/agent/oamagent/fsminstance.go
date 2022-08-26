package oamagent

import (
	"lite5gc/cmn/fsm"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/oam/agent"
)

type UpfFsmInstance struct {
	*agent.FsmInstance
	*UpfFsmWorker
}

func CreateUpfFsmInstance(w *UpfFsmWorker) *UpfFsmInstance {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	p := new(UpfFsmInstance)
	p.FsmInstance, _ = agent.CreateFsmInstance(p)
	p.UpdateWorker(w)
	return p
}

func (p *UpfFsmInstance) UpdateWorker(w *UpfFsmWorker) {
	p.UpfFsmWorker = w
}

func (p *UpfFsmInstance) RegisterStart(e *fsm.Event) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	p.RegisterPeriod()
}

func (p *UpfFsmInstance) RegisterResp(e *fsm.Event) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	go p.HeartBeat()
}

func (p *UpfFsmInstance) HbeatStop(e *fsm.Event) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	p.RegisterPeriod()
}
