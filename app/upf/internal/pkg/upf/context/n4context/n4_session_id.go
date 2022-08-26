package n4context

import (
	"lite5gc/cmn/idmgr64"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/utils"
)

// UPF assign the SEID
// uint64 类型，核心网内唯一
func GetSEID() (uint64, error) {
	rlogger.FuncEntry(moduleTag, nil)
	idmgr64.GetInst().RegisterIDMgr(string(types.SmfSEID), types.MaxNumSmfSeid)
	seid, err := idmgr64.GetInst().BorrowID(string(types.SmfSEID))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils.Seid(seid), "SMF assign the SEID failed:%s", err)
	}
	return seid, err
}
