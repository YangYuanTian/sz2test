package pdr

import (
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/utils"
)

func GetSeidFromIp(ip string) (uint64, error) {
	rlogger.FuncEntry(moduleTag, nil)
	dst := &ueIpN4SessionTable

	if value, ok := dst.Get(ip).(UEIpN4SessionValue); ok {
		rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(value.SEID), "get SEID:%v", value.SEID)
		return value.SEID, nil
	}

	err := ErrNoMatchSession //errors.New("No matching session")
	//rlogger.Trace(moduleTag, rlogger.ERROR, nil,  "No matching session")
	return 0, err
}

// teid to seid
func GetSeidFromTeid(teid uint32) (uint64, error) {
	//td := &rlogger.TraceV{types.TEID_TRACE, teid}
	rlogger.FuncEntry(moduleTag, nil)
	dst := &teidMatchingN4N4SessionTable

	if value, ok := dst.Get(teid).(TEIdN4SessionValue); ok {
		rlogger.Trace(moduleTag, rlogger.INFO, utils.Seid(value.SEID), "get SEID:%v", value.SEID)
		return value.SEID, nil
	}

	err := ErrNoMatchSession //errors.New("No matching session")
	rlogger.Trace(moduleTag, rlogger.WARN, nil, "No matching session")
	return 0, err
}
