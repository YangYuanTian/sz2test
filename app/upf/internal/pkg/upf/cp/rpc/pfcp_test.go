package rpc

import (
	"context"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types/configure"
	"sync"
	"testing"
	"time"

	"lite5gc/cmn/types"
	. "lite5gc/upf/cp/n4layer"
)

func TestUpfN4ResponseMsg(t *testing.T) {
	upfCtxt := &types.AppContext{
		Name:     "upf",
		Wg:       &sync.WaitGroup{},
		ConfPath: types.DEF_CONF_FILE_UPF,
	}
	upfCtxt.Ctx, upfCtxt.Cancel = context.WithCancel(context.Background())
	//load common configuration from amf config file
	err := configure.LoadConfigCmn("ini", types.DEF_CONF_FILE_UPF)
	if err != nil {
		panic("load common config file failed")
	}

	//load config
	var confPath = types.DEF_CONF_FILE_UPF
	err = configure.LoadConfigUPF("ini", confPath)
	if err != nil {
		panic("load upf config file failed")
	}

	////tag
	//start rlogger
	rlogger.Init()

	// 当前开启N4 tcp server
	errN4 := StartN4Server(upfCtxt)
	if errN4 != nil {
		panic("Failed to start n4 socket server ")
	}

	time.Sleep(30e9)
	N4SessionReportRequest(nil, nil)
	upfCtxt.Wg.Wait()
}

func TestUpfN4RequestMsg(t *testing.T) {
	upfCtxt := &types.AppContext{
		Name:     "upf",
		Wg:       &sync.WaitGroup{},
		ConfPath: types.DEF_CONF_FILE_UPF,
	}
	upfCtxt.Ctx, upfCtxt.Cancel = context.WithCancel(context.Background())
	// 发送 报告到smf

	N4SessionReportRequest(nil, nil)
}
