package oamagent

import (
	"context"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/timermgr"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/agent"
)

func StartUpfOamAgent(ctx context.Context) {
	// create upf regis&hbeat fsm
	timerMgr := timermgr.NewTimerMgr(ctx, 1, 200)
	rlogger.Trace(types.ModuleUpfAgent, rlogger.DEBUG, nil, "StartOamAgent start TimerMgr %p", timerMgr)
	ctx = context.WithValue(ctx, types.OamTimerMgrCK, timerMgr)
	upfFsmInstance := CreateUpfFsmInstance(nil)
	upfFsmWorker := CreateUpfFsmWorker(ctx, upfFsmInstance.FsmInstance)
	upfFsmInstance.UpdateWorker(upfFsmWorker)

	upfReportMgr := CreateUPFReporter(ctx, upfFsmInstance.FsmInstance)
	upfReportMgr.StartReport()

	// create upf agent for web
	httpServer := CreateUpfHttpServer(upfFsmInstance.FsmInstance)
	httpServer.Run()

	if configure.SysConf.EnableWeb == true {
		rlogger.Trace(types.ModuleUpfAgent, rlogger.DEBUG, nil, "before EventRegStart upfFsmInstance.Bfsm: \n%s", upfFsmInstance.FsmInstance)
		upfFsmInstance.FsmInstance.Bfsm.Event(agent.EventRegStart)
		rlogger.Trace(types.ModuleUpfAgent, rlogger.DEBUG, nil, "after EventRegStart upfFsmInstance.Bfsm: \n%s", upfFsmInstance.FsmInstance)

	}
}
