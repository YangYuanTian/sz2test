package oamagent

import (
	"errors"
	"fmt"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/agent"
	"lite5gc/oam/agent/webTypes"
	"lite5gc/oam/cli/cmd"
	"net/http"
	"strconv"
	"strings"
)

// UPF DnnInfo Add Delete Edit Get
// UPF Edit
func (p *UpfHttpServer) UpfSettingDnnInfoedit(w http.ResponseWriter, req *http.Request) {

	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")
	index := req.URL.Query().Get("id")
	indexs, err := strconv.Atoi(index)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var t configure.DNNInformation
	err1 := agent.ParseReqData(req, &t)
	if err1 != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	err = cmd.ValidateIp(t.DnnIp)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		err1 := errors.New("dnnIp  ipv4 format setting error")
		agent.RespSettingError(w, err1, nil)
		return
	}
	if t.DnnIpv6 != "" {
		err = cmd.ValidateIpv6(t.DnnIpv6)
		if err != nil {
			err := errors.New("dnn ipv6 format error ")
			agent.RespSettingError(w, err, nil)
			return
		}
	}
	var flag int
	flag = 0
	var b []configure.CmDNNInformation
	data := configure.CmUpfConf.DnnInfo
	str := cmd.GainDnnInfoDnnEdit(data, indexs)
	err2 := cmd.ValidateRepetitionDnn(str, t.Dnn)
	if err2 != nil {
		agent.RespSettingError(w, err2, nil)
		return
	}
	for _, v := range data {
		logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, v.Index)
		if v.Index == indexs {
			flag = 1
			v.Dnn = strings.ToLower(t.Dnn)
			v.DnnIp = t.DnnIp
			v.DnnIpv6 = t.DnnIpv6
			v.DnnNameIpRangeString = t.DnnNameIpRangeString
			v.DnnSnssaiUpfIpString = t.DnnSnssaiUpfIpString
			b = append(b, v)
		} else {
			b = append(b, v)
		}
	}
	configure.CmUpfConf.DnnInfo = b
	w.Header().Set("Content-Type", "application-json")
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", b)
	} else {
		err := errors.New("There is no matching index ID of DnnInfo ")
		agent.RespSettingError(w, err, nil)
		return
	}
	agent.TakeEffectUpfConf(4)
	agent.TakeEffect("upf", "dnninfo")
	original.OldData = data
	original.NewData = configure.CmUpfConf.DnnInfo
	str1 := fmt.Sprintf("edit configure upf Data Network")
	agent.OperationLogs(host, "UPF", str1, original)
}

// DnnInfo Add
func GetMaxDnnInfoId(p []configure.CmDNNInformation) int {
	max := 0
	for _, v := range p {
		if max < v.Index {
			max = v.Index
		}
	}
	return max + 1
}

func (p *UpfHttpServer) UpfSettingDnnInfoAdd(w http.ResponseWriter, req *http.Request) {

	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "upf setting dnninfo add ")
	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")
	var t configure.DNNInformation
	err := agent.ParseReqData(req, &t)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	err = cmd.ValidateIp(t.DnnIp)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		err1 := errors.New("dnnIp ipv4 format setting error")
		agent.RespSettingError(w, err1, nil)
		return
	}
	if t.DnnIpv6 != "" {
		err = cmd.ValidateIpv6(t.DnnIpv6)
		if err != nil {
			err := errors.New("dnn ipv6 format error ")
			agent.RespSettingError(w, err, nil)
			return
		}

	}
	var b configure.CmDNNInformation
	data := configure.CmUpfConf.DnnInfo
	str := cmd.GainDnnInfoDnn(data)
	err1 := cmd.ValidateRepetitionDnn(str, t.Dnn)
	if err1 != nil {
		agent.RespSettingError(w, err1, nil)
		return
	}

	b.Index = GetMaxDnnInfoId(data)
	b.Dnn = strings.ToLower(t.Dnn)
	b.DnnIp = t.DnnIp
	b.DnnIpv6 = t.DnnIpv6
	b.DnnNameIpRangeString = t.DnnSnssaiUpfIpString
	b.DnnSnssaiUpfIpString = t.DnnSnssaiUpfIpString
	configure.CmUpfConf.DnnInfo = append(data, b)
	w.Header().Set("Content-Type", "application-json")
	agent.RespSettingSuccess(w, "successful", b)
	agent.TakeEffectUpfConf(4)
	agent.TakeEffect("upf", "dnninfo")

	original.OldData = data
	original.NewData = configure.CmUpfConf.DnnInfo
	str1 := fmt.Sprintf("add configure upf Data Network")
	agent.OperationLogs(host, "UPF", str1, original)

}

// DnnInfo Delete
func (p *UpfHttpServer) UpfSettingDnnInfoDelete(w http.ResponseWriter, req *http.Request) {

	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")
	index := req.URL.Query().Get("id")
	indexs, err := strconv.Atoi(index)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var flag int
	flag = 0
	var b []configure.CmDNNInformation
	w.Header().Set("Content-Type", "application-json")
	data := configure.CmUpfConf.DnnInfo
	for _, v := range data {
		if v.Index != indexs {
			b = append(b, v)
		} else {
			flag = 1
		}
	}
	configure.CmUpfConf.DnnInfo = b
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", indexs)
	} else {
		err := errors.New("There is no matching index ID of DnnInfo ")
		agent.RespSettingError(w, err, indexs)
		return
	}
	agent.TakeEffectUpfConf(4)
	agent.TakeEffect("upf", "dnninfo")
	original.OldData = data
	original.NewData = configure.CmUpfConf.DnnInfo
	str1 := fmt.Sprintf("delete configure upf Data Network")
	agent.OperationLogs(host, "UPF", str1, original)
}

// DnnInfo Get
func (p *UpfHttpServer) UpfSettingDnnInfoGetData(w http.ResponseWriter, req *http.Request) {
	index := req.URL.Query().Get("id")
	indexs, err := strconv.Atoi(index)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var flag int
	flag = 0
	var b configure.CmDNNInformation
	w.Header().Set("Content-Type", "application-json")
	data := configure.CmUpfConf.DnnInfo
	for _, v := range data {
		if v.Index == indexs {
			flag = 1
			b.Index = indexs
			b.Dnn = v.Dnn
			b.DnnIp = v.DnnIp
			b.DnnIpv6 = v.DnnIpv6
			b.DnnNameIpRangeString = v.DnnNameIpRangeString
			b.DnnSnssaiUpfIpString = v.DnnSnssaiUpfIpString
		}
	}
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", b)
	} else {
		err := errors.New("There is no data to query ")
		agent.RespSettingError(w, err, nil)
	}
}
