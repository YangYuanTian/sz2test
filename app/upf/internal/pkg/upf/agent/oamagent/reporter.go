package oamagent

import (
	"context"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/agent"
	"lite5gc/oam/agent/webTypes"
	"lite5gc/upf/metrics"
	// "lite5gc/oam/agent/webTypes"
)

type UpfReporter struct {
	agent.IReportData
	*agent.ReporterBase
}

var NFInfo webTypes.NfNoInfo

func CreateUPFReporter(ctx context.Context, fsm *agent.FsmInstance) *UpfReporter {
	p := new(UpfReporter)
	p.ReporterBase = agent.CreateReporterBase(ctx, fsm, p, configure.SysConf.WebAddr, configure.SysConf.SmallwebAddr)
	return p
}

func (p *UpfReporter) PerformData() *webTypes.NfPerformanceData {
	return performData()
}

// performData
func performData() *webTypes.NfPerformanceData {
	return metrics.ReportToLems(UpfNfName)
}
