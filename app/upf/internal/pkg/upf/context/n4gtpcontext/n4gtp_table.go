/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/3/30 17:22
* Description:
 */
package n4gtpcontext

import (
	"fmt"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/syncmap"
	"lite5gc/cmn/types"
)

type N4GtpEntry struct {
	Teid uint32 // n4 gtp upf teid
	Seid uint64 // n4 pfcp upf seid
}

var n4GtpTable syncmap.SyncMap //key:teid uint32,value: &N4GtpEntry

func ValuesOfTbl() (CxtList []*N4GtpEntry, err error) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	n4GtpTable.Range(func(key, value interface{}) bool {
		//fmt.Println(key, value)
		ctxt, ok := value.(*N4GtpEntry)
		if !ok {
			err = fmt.Errorf("invalid node type")
			return false
		}
		CxtList = append(CxtList, ctxt)
		return true
	})

	return
}

func Add(key uint32, ctxt *N4GtpEntry) error {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	var err error

	err = n4GtpTable.Set(key, ctxt)
	if err != nil {
		err = fmt.Errorf("failed to set key(%s),err(%s)", key, err)
	}

	return err
}

func Get(key uint32) (n *N4GtpEntry, err error) {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	val := n4GtpTable.Get(key)
	if val == nil {
		err = fmt.Errorf("failed to find with key(%s)", key)
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	ctxt, ok := val.(*N4GtpEntry)
	if !ok {
		err = fmt.Errorf("invalid node type")
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	n = ctxt
	//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
	return
}

func Update(key uint32, n *N4GtpEntry) error {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	if n == nil {
		return fmt.Errorf("invalid input parameter, nil Node")
	}

	n4GtpTable.Update(key, n)

	return nil
}

func Delete(key uint32) error {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	n4GtpTable.Del(key)

	return nil
}

func LengthOfTbl(key uint32) uint64 {
	rlogger.FuncEntry(types.ModuleSmfN4, nil)
	var length uint64
	length = n4GtpTable.Length64()

	return length
}
