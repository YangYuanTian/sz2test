package oamagent

import (
	"fmt"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	userstrace2 "lite5gc/cmn/userstrace"
	"lite5gc/oam/agent"
	"lite5gc/oam/agent/webTypes"
	"lite5gc/upf/service/userstrace"
	"net/http"
	"strings"
)

var PacketData webTypes.DumpSet

func TestKey() {
	userstrace2.SetUserID(fmt.Sprintf("%s46000001", userstrace2.PrefixIMSI))
	userstrace2.SetUserID(fmt.Sprintf("%s46000002", userstrace2.PrefixIMSI))
	userstrace2.SetUserID(fmt.Sprintf("%s46000003", userstrace2.PrefixIMSI))
	userstrace2.SetUserID(fmt.Sprintf("%s46000004", userstrace2.PrefixIMSI))
	userstrace2.SetUserID(fmt.Sprintf("%s46000005", userstrace2.PrefixIMSI))
	userstrace2.SetUserID(fmt.Sprintf("%s46000006", userstrace2.PrefixIMSI))
	userstrace2.SetUserID(fmt.Sprintf("%s46000007", userstrace2.PrefixIMSI))
	userstrace2.SetUserID(fmt.Sprintf("%s46000008", userstrace2.PrefixSEID))
	userstrace2.SetUserID(fmt.Sprintf("%s46000009", userstrace2.PrefixTEID))
	userstrace2.SetUserID(fmt.Sprintf("%s460000010", userstrace2.PrefixUEIP))
}

func (p *UpfHttpServer) GetAllKey(w http.ResponseWriter, req *http.Request) {
	var strs []webTypes.User
	var str webTypes.User
	//TestKey()
	data := userstrace2.GetALLUserID()
	if len(data) == 0 || data == nil {
		fmt.Println("get user data len 0")
	}
	fmt.Println("get user num:", len(data))
	for _, v := range data {
		if strings.Contains(v, "IMSI_") == true {
			str.Usertype = "imsi"
			split := strings.Split(v, "IMSI_")
			str.Userlist = split[1]
		} else if strings.Contains(v, "TEID") == true {
			str.Usertype = "teid"
			split := strings.Split(v, "TEID_0x")
			str.Userlist = split[1]
		} else if strings.Contains(v, "UEIP") == true {
			str.Usertype = "ueip"
			split := strings.Split(v, "UEIP_")
			str.Userlist = split[1]

		} else if strings.Contains(v, "SEID") == true {
			str.Usertype = "seid"
			split := strings.Split(v, "SEID_0x")
			str.Userlist = split[1]
		} else {
			str.Usertype = "string"
			str.Userlist = v
		}
		strs = append(strs, str)
	}
	da := webTypes.ParamResponData{ErrorNo: 200, ErrorMessage: "setting successful", Params: strs}
	agent.RespData(w, da)
}

func (p *UpfHttpServer) SettingDumpPacket(w http.ResponseWriter, req *http.Request) {
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "setting dump packet")
	err := agent.ParseReqData(req, &PacketData)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "param bindind failed %s", err)
		data := webTypes.ParamResponData{ErrorNo: 500, ErrorMessage: "param binding error", Params: err}
		agent.RespData(w, data)
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", PacketData)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "setting dump packet successful")
	data := webTypes.ParamResponData{ErrorNo: 200, ErrorMessage: "setting successful", Params: nil}
	agent.RespData(w, data)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, PacketData.User)
	userstrace2.SetUserCaptureList(userstrace2.Transition(PacketData.User))
}

func (p *UpfHttpServer) StartDumpPacket(w http.ResponseWriter, req *http.Request) {
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "start dump packet")
	var data webTypes.ParamData
	err := agent.ParseReqData(req, &data)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "param binding failed %s", err)
		resp := webTypes.ParamResponData{ErrorNo: 500, ErrorMessage: "param binding error", Params: err}
		agent.RespData(w, resp)
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", data)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", data)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", data)
	err = userstrace.Start()
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "start dump packet failed %s", err)
		resp := webTypes.ParamResponData{ErrorNo: 500, ErrorMessage: "error " + err.Error(), Params: err.Error()}
		agent.RespData(w, resp)
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "dump packet successful")
	resp := webTypes.ParamResponData{ErrorNo: 200, ErrorMessage: "successful", Params: nil}
	agent.RespData(w, resp)
}

func (p *UpfHttpServer) StopDumpPacket(w http.ResponseWriter, req *http.Request) {
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "stop dump packet")
	var data webTypes.StopDump
	err := agent.ParseReqData(req, &data)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "param binding failed %s", err)
		resp := webTypes.ParamResponData{ErrorNo: 500, ErrorMessage: "param binding error", Params: err}
		agent.RespData(w, resp)
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", data)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", data)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "%#v", data)
	//stop dump packet
	err = userstrace.Stop()
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "stop dump packet failed %s", err)
		resp := webTypes.ParamResponData{ErrorNo: 500, ErrorMessage: "error " + err.Error(), Params: err}
		agent.RespData(w, resp)
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "stop dump packet successful")
	resp := webTypes.ParamResponData{ErrorNo: 200, ErrorMessage: "successful", Params: nil}
	agent.RespData(w, resp)
}
