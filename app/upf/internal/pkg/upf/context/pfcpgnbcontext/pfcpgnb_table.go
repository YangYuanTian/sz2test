/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/3/30 17:22
* Description:
 */
package pfcpgnbcontext

import (
	"fmt"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/syncmap"
	"lite5gc/cmn/types"
	"lite5gc/upf/stateless/recoverdata"
)

var pfcpGnbTable syncmap.SyncMap //key:(pfcp ip + gnb ip)string,value: *GnbInfo

func ValuesOfTbl() (CxtList []*PfcpGnbInfo, err error) {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	pfcpGnbTable.Range(func(key, value interface{}) bool {
		//fmt.Println(key, value)
		ctxt, ok := value.(*PfcpGnbInfo)
		if !ok {
			err = fmt.Errorf("invalid node type")
			return false
		}
		CxtList = append(CxtList, ctxt)
		return true
	})

	return
}

func Add(key string, ctxt *PfcpGnbInfo) error {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	var err error

	err = pfcpGnbTable.Set(key, ctxt)
	if err != nil {
		err = fmt.Errorf("failed to set key(%s),err(%s)", key, err)
	}
	recoverdata.AddPfcpGnbToRedis(key, ctxt)
	return err
}
func AddPfcpGnbFromRedis(key string, ctxt *PfcpGnbInfo) error {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	var err error
	err = pfcpGnbTable.Set(key, ctxt)
	if err != nil {
		err = fmt.Errorf("failed to set key(%s),err(%s)", key, err)
	}
	return err
}

func Get(key string) (n *PfcpGnbInfo, err error) {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	val := pfcpGnbTable.Get(key)
	if val == nil {
		err = fmt.Errorf("failed to find Node with peerIp key(%s)", key)
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	ctxt, ok := val.(*PfcpGnbInfo)
	if !ok {
		err = fmt.Errorf("invalid node type")
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	n = ctxt
	//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
	return
}

func Update(key string, n *PfcpGnbInfo) error {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	if n == nil {
		return fmt.Errorf("invalid input parameter, nil Node")
	}

	pfcpGnbTable.Update(key, n)

	return nil
}

func Delete(key string) error {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	pfcpGnbTable.Del(key)
	recoverdata.DeletePfcpGnbInRedis(key)
	return nil
}

func LengthOfTbl(key string) uint64 {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	var length uint64
	length = pfcpGnbTable.Length64()

	return length
}
