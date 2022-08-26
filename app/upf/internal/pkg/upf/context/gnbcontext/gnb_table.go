/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/3/30 17:22
* Description:
 */
package gnbcontext

import (
	"fmt"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/syncmap"
	"upf/internal/pkg/cmn/types"
)

var gnbTable syncmap.SyncMap    //key:ip string,value: *GnbInfo
var PsaUpfTable syncmap.SyncMap //key:ip string,value:*PsaUpfTable
func ValuesOfGnbTbl() (CxtList []*GnbInfo, err error) {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	gnbTable.Range(func(key, value interface{}) bool {
		//fmt.Println(key, value)
		ctxt, ok := value.(*GnbInfo)
		if !ok {
			err = fmt.Errorf("invalid node type")
			return false
		}
		CxtList = append(CxtList, ctxt)
		return true
	})

	return
}

func AddGnb(key string, ctxt *GnbInfo) error {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	var err error

	err = gnbTable.Set(key, ctxt)
	if err != nil {
		err = fmt.Errorf("failed to set key(%s),err(%s)", key, err)
	}

	return err
}

func GetGnb(key string) (n *GnbInfo, err error) {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	val := gnbTable.Get(key)
	if val == nil {
		err = fmt.Errorf("failed to find Node with peerIp key(%s)", key)
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	ctxt, ok := val.(*GnbInfo)
	if !ok {
		err = fmt.Errorf("invalid node type")
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	n = ctxt
	//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
	return
}

func UpdateGnb(key string, n *GnbInfo) error {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	if n == nil {
		return fmt.Errorf("invalid input parameter, nil Node")
	}

	gnbTable.Update(key, n)

	return nil
}

func DeleteGnb(key string) error {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	gnbTable.Del(key)

	return nil
}

func LengthOfGnbTbl(key string) uint64 {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	var length uint64
	length = gnbTable.Length64()

	return length
}
