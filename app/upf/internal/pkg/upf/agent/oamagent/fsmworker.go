package oamagent

import (
	"context"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/cmn/utils"
	"lite5gc/oam/agent"
	"lite5gc/oam/agent/webTypes"
)

var UpfNfName string

type UpfFsmWorker struct {
	*agent.FsmWorker
}

func CreateUpfFsmWorker(ctx context.Context, fsm *agent.FsmInstance) *UpfFsmWorker {
	p := new(UpfFsmWorker)
	p.FsmWorker = agent.CreateFsmWorker(ctx, fsm, p, configure.SysConf.WebAddr)
	return p
}

func (p *UpfFsmWorker) RegisterData() *webTypes.RegData {
	md5 := utils.GetHostInfoMd5Nf("UPF")
	formatMd5, err := utils.FormatMd5(md5)
	UpfNfName = formatMd5
	if err != nil {
		rlogger.Trace(types.ModuleUpfAgent, rlogger.ERROR, nil, "FormatMd5 fail %s", err.Error())
	}
	regdata := webTypes.RegData{
		NfType:    "UPF",
		NfName:    formatMd5,
		Version:   "v" + configure.UpfConf.Version.Main,
		NfIp:      configure.SysConf.NfIp,
		NfPort:    8892,
		MessageId: 0,
	}
	return &regdata
}

func (p *UpfFsmWorker) HeartBeatData() *webTypes.HeartBeatData {
	heartBeatData := webTypes.HeartBeatData{NfNo: p.FsmNfNO}
	return &heartBeatData
}
