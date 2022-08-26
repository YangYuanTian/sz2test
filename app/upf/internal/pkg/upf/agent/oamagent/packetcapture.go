package oamagent

import (
	"errors"
	"fmt"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/agent"
	"lite5gc/oam/agent/webTypes"
	"net/http"
	"strconv"
)

// UPF PacketCapture Add Delete Edit Get URL
// UPF PacketCapture Edit URL
func (p *UpfHttpServer) UpfSettingPacketCaptureEdit(w http.ResponseWriter, req *http.Request) {

	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")
	index := req.URL.Query().Get("id")
	indexs, err := strconv.Atoi(index)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var t configure.PktCapInfo
	err1 := agent.ParseReqData(req, &t)
	if err1 != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var flag int
	flag = 0
	var b []configure.CmPktCapInfo
	data := configure.CmUpfConf.PacketCapture
	for _, v := range data {
		if v.Index == indexs {
			flag = 1
			v.Recv = t.Recv
			v.Send = t.Send
			v.PoolCoeff = t.PoolCoeff
			v.OutDir = t.OutDir
			v.PortId = t.PortId
			b = append(b, v)
		} else {
			b = append(b, v)
		}
	}
	configure.CmUpfConf.PacketCapture = b
	w.Header().Set("Content-Type", "application-json")
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", b)
	} else {
		err := errors.New("There is no matching index ID of PacketCapture ")
		agent.RespSettingError(w, err, nil)
	}
	agent.TakeEffect("upf", "packetcapture")
	original.OldData = data
	original.NewData = configure.CmUpfConf.PacketCapture
	str1 := fmt.Sprintf("edit configure upf PacketCapture")
	agent.OperationLogs(host, "UPF", str1, original)
}

// PacketCapture Add URL
func GetMaxPacketCaptureId(p []configure.CmPktCapInfo) int {
	max := 0
	for _, v := range p {
		if max < v.Index {
			max = v.Index
		}
	}
	return max + 1
}
func (p *UpfHttpServer) UpfSettingPacketCaptureAdd(w http.ResponseWriter, req *http.Request) {
	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")

	var t configure.PktCapInfo
	err := agent.ParseReqData(req, &t)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var b configure.CmPktCapInfo
	data := configure.CmUpfConf.PacketCapture
	b.Index = GetMaxPacketCaptureId(data)
	b.Recv = t.Recv
	b.Send = t.Send
	b.PortId = t.PortId
	b.OutDir = t.OutDir
	b.PoolCoeff = t.PoolCoeff
	configure.CmUpfConf.PacketCapture = append(data, b)
	w.Header().Set("Content-Type", "application-json")
	agent.RespSettingSuccess(w, "successful", b)
	agent.TakeEffect("upf", "packetcapture")
	original.OldData = data
	original.NewData = configure.CmUpfConf.PacketCapture
	str1 := fmt.Sprintf("add configure upf PacketCapture")
	agent.OperationLogs(host, "UPF", str1, original)

}

// PacketCapture Delete URL
func (p *UpfHttpServer) UpfSettingPacketCaptureDelete(w http.ResponseWriter, req *http.Request) {
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
	var b []configure.CmPktCapInfo
	w.Header().Set("Content-Type", "application-json")
	data := configure.CmUpfConf.PacketCapture
	for _, v := range data {
		if v.Index != indexs {
			b = append(b, v)
		} else {
			flag = 1
		}
	}
	configure.CmUpfConf.PacketCapture = b
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", indexs)
	} else {
		err := errors.New("There is no matching index ID of DnnInfo ")
		agent.RespSettingError(w, err, indexs)
	}
	agent.TakeEffect("upf", "packetcapture")
	original.OldData = data
	original.NewData = configure.CmUpfConf.PacketCapture
	str1 := fmt.Sprintf("delete configure upf PacketCapture")
	agent.OperationLogs(host, "UPF", str1, original)
}

// PacketCapture Get URL
func (p *UpfHttpServer) UpfSettingPacketCaptureGetData(w http.ResponseWriter, req *http.Request) {

	index := req.URL.Query().Get("id")
	indexs, err := strconv.Atoi(index)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		return
	}
	var flag int
	flag = 0
	var b configure.CmPktCapInfo
	w.Header().Set("Content-Type", "application-json")
	data := configure.CmUpfConf.PacketCapture
	for _, v := range data {
		if v.Index == indexs {
			flag = 1
			b.Index = indexs
			b.Recv = v.Recv
			b.Send = v.Send
			b.OutDir = v.OutDir
			b.PoolCoeff = v.PoolCoeff
			b.PortId = v.PortId
		}
	}
	if flag == 1 {
		agent.RespSettingSuccess(w, "successful", b)
	} else {
		err := errors.New("There is no data to query ")
		agent.RespSettingError(w, err, nil)
	}
}
