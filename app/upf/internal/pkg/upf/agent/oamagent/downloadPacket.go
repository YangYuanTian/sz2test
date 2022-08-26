package oamagent

import (
	"fmt"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/userstrace"
	"lite5gc/oam/agent"
	"lite5gc/oam/agent/webTypes"
	"net/http"
	"os"
)

const (
	captureFileUpfSavePath = "./pcap/"
)

func (p *UpfHttpServer) GetAllPacketFiles(w http.ResponseWriter, req *http.Request) {
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "get all packet file information")
	capFiles, err := userstrace.GetAllCapFiles(captureFileUpfSavePath)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "get packet file failed %s", err)
		resp := webTypes.ParamResponData{ErrorNo: 500, ErrorMessage: "param binding error", Params: err}
		agent.RespData(w, resp)
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "get all packet file successful")
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", capFiles)
	resp := webTypes.ParamResponData{ErrorNo: 200, ErrorMessage: "successful", Params: capFiles}
	agent.RespData(w, resp)
}

func (p *UpfHttpServer) DeletePacketFile(w http.ResponseWriter, req *http.Request) {
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "delete packet file")
	filename := req.URL.Query().Get("filename")
	if filename == "" {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "delete file nonexistence")
		resp := webTypes.ParamResponData{500, "delete file nonexistence", nil}
		agent.RespData(w, resp)
		return
	}
	err := os.Remove(filename)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		resp := webTypes.ParamResponData{500, "remove file failed", err}
		agent.RespData(w, resp)
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "file delete successful")
	resp := webTypes.ParamResponData{200, "successful", nil}
	agent.RespData(w, resp)
}

func (p *UpfHttpServer) DownloadCaptureFile(w http.ResponseWriter, req *http.Request) {
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "download capture file")
	filename := req.URL.Query().Get("filename")
	if filename == "" {
		resp := webTypes.ParamResponData{500, "file nonexistence", nil}
		agent.RespData(w, resp)
		return
	}
	w.Header().Add("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Add("Content-Type", "application/octet-stream") //ÔÊÐíä¯ÀÀÆ÷ÏÂÔØÎÄ¼þ  ·ûºÏ±ê×¼
	http.ServeFile(w, req, filename)
}
