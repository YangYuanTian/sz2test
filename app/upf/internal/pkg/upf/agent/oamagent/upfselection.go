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

// UpfSelection  Edit
func (p *UpfHttpServer) UpfSettingUpfSelectionedit(w http.ResponseWriter, req *http.Request) {

	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")
	index := req.URL.Query().Get("id")
	indexs, err := strconv.Atoi(index)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var t configure.UpfSelection
	err1 := agent.ParseReqData(req, &t)
	if err1 != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var flag int
	flag = 0
	var b []configure.CmUpfSelection
	data := configure.CmUpfConf.UpfSel
	data2 := cmd.GainUpfSeNameEdit(data, indexs)
	err2 := cmd.ValidateRepetitionTai(data2, t.DnnName, t.Tai)
	if err2 != nil {
		err := errors.New("upfselection dnnname already existed ")
		agent.RespSettingError(w, err, nil)
		return
	}

	for _, v := range data {
		logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%s  %s", v.Index, data)
		if v.Index == indexs {
			flag = 1
			v.DnnName = strings.ToLower(t.DnnName)
			v.Snssai = t.Snssai
			v.Tai = t.Tai
			v.UpfIp = t.UpfIp
			b = append(b, v)
		} else {
			b = append(b, v)
		}
	}
	w.Header().Set("Content-Type", "application-json")
	configure.CmUpfConf.UpfSel = b
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", b)
	} else {
		err := errors.New("There is no matching index ID of upf ")
		agent.RespSettingError(w, err, nil)
		return
	}
	agent.TakeEffect("upf", "upfselection")
	agent.TakeEffectUpfConf(webTypes.UPFSelection)
	original.OldData = data
	original.NewData = configure.CmUpfConf.UpfSel
	str1 := fmt.Sprintf("edit configure upf upfselection")
	agent.OperationLogs(host, "UPF", str1, original)

}

// Upfselection add
func GetUpfSelectionMaxId1(p []configure.CmUpfSelection) int {
	max := 0
	for _, v := range p {
		if max < v.Index {
			max = v.Index
		}
	}
	return max + 1
}

func (p *UpfHttpServer) UpfSettingUpfSelectionAdd(w http.ResponseWriter, req *http.Request) {

	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")
	var t configure.UpfSelection
	err := agent.ParseReqData(req, &t)
	if err != nil {
		logger.Trace(types.ModuleSmfAgent, logger.ERROR, nil, err)
		return
	}
	var b configure.CmUpfSelection
	data := configure.CmUpfConf.UpfSel
	err1 := cmd.ValidateRepetitionTai(data, t.DnnName, t.Tai)
	if err1 != nil {
		err := errors.New("upfselection dnnname already existed")
		agent.RespSettingError(w, err, nil)
		return
	}
	b.Index = GetUpfSelectionMaxId1(data)
	b.DnnName = strings.ToLower(t.DnnName)
	b.Snssai = t.Snssai
	b.Tai = t.Tai
	b.UpfIp = t.UpfIp
	w.Header().Set("Content-Type", "application-json")
	configure.CmUpfConf.UpfSel = append(data, b)

	agent.RespSettingSuccess(w, "successful", b)
	agent.TakeEffect("upf", "upfselection")
	agent.TakeEffectUpfConf(webTypes.UPFSelection)
	original.OldData = data
	original.NewData = configure.CmUpfConf.UpfSel
	str1 := fmt.Sprintf("add configure upf upfselection")
	agent.OperationLogs(host, "UPF", str1, original)

}

// upfselection  delete
func (p *UpfHttpServer) UpfSettingUpfSelectionDelete(w http.ResponseWriter, req *http.Request) {

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
	var b []configure.CmUpfSelection
	data := configure.CmUpfConf.UpfSel
	for _, v := range data {
		if v.Index != indexs {
			b = append(b, v)
		} else {
			flag = 1
		}
	}
	w.Header().Set("Content-Type", "application-json")
	configure.CmUpfConf.UpfSel = b
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", index)
	} else {
		err := errors.New("There is no matching index ID of upf ")
		agent.RespSettingError(w, err, nil)
		return
	}
	agent.TakeEffect("upf", "upfselection")
	agent.TakeEffectUpfConf(webTypes.UPFSelection)
	original.OldData = data
	original.NewData = configure.CmUpfConf.UpfSel
	str1 := fmt.Sprintf("delete configure upf upfselection")
	agent.OperationLogs(host, "UPF", str1, original)
}

// upfselection get data
func (p *UpfHttpServer) UpfSettingUpfSelectionGetData(w http.ResponseWriter, req *http.Request) {
	values := req.URL.Query()
	index := values.Get("id")
	indexs, err := strconv.Atoi(index)
	if err != nil {
		logger.Trace(types.ModuleSmfAgent, logger.ERROR, nil, err)
		return
	}
	var flag int
	flag = 0
	var b configure.CmUpfSelection
	w.Header().Set("Content-Type", "application-json")
	data := configure.CmUpfConf.UpfSel
	for _, v := range data {
		if v.Index == indexs {
			flag = 1
			b.Index = indexs
			b.DnnName = v.DnnName
			b.Snssai = v.Snssai
			b.Tai = v.Tai
			b.UpfIp = v.UpfIp
		}
	}
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", b)
	} else {
		err := errors.New("There is no data to query ")
		agent.RespSettingError(w, err, nil)
	}
}
