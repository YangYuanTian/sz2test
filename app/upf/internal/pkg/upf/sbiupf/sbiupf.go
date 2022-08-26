/*
* Copyright(C),2020-2022
* Author: xy
* Description:
 */
package sbiupf

import (
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/sbicmn"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/openapi/models"
	"lite5gc/upf/sbiupf/httpcallback"
	"sync"
	"time"
)

var SbiUpf sbicmn.SbiInterface

func UpfSbiInitialize() error {
	rlogger.FuncEntry(types.ModuleUpfSbi, nil)
	SbiUpf.Initialize(configure.UpfConf.Sbi.Upf.Addr.Ip,
		configure.UpfConf.Sbi.Upf.Addr.Port,
		configure.UpfConf.Sbi.Upf.Scheme, models.NfType_UPF, configure.CmSysConf.GinMode)

	rlogger.Trace(types.ModuleAmfHttpCallback, rlogger.INFO, nil,
		"configure.UpfConf.Sbi(%v)", configure.UpfConf.Sbi)
	SbiUpf.SetSbiLogger()

	//add service
	httpcallback.NewRouter(SbiUpf.GetRouter())

	//start listening...
	err := SbiUpf.Start()
	if err != nil {
		return err
	}
	return nil
}

var mutex = &sync.Mutex{}

func SbiUpfRestart() error {
	mutex.Lock()
	defer mutex.Unlock()
	err := SbiUpf.HttpServer.Close()
	if err != nil {
		return err
	}
	SbiUpf = sbicmn.SbiInterface{}
	err = UpfSbiInitialize()
	if err != nil {
		return err
	}
	time.Sleep(time.Second / 2)
	return nil
}
