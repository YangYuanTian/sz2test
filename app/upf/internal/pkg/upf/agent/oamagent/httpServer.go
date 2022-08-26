package oamagent

import (
	"encoding/json"
	"errors"
	"fmt"
	"lite5gc/cmn/jwt"
	"lite5gc/cmn/rlogger"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/cmn/utils"
	"lite5gc/oam/agent"
	"lite5gc/oam/agent/webTypes"
	"lite5gc/oam/cli/cmd"
	"lite5gc/oam/cm/yaml"
	oamagent "lite5gc/upf/agent/cmdagent"
	"lite5gc/upf/envinit"
	"lite5gc/upf/metrics"
	"lite5gc/upf/nff"
	"lite5gc/upf/sbiupf"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type UpfHttpServer struct {
	*agent.HttpServer
	*agent.FsmInstance
}

func CreateUpfHttpServer(fsm *agent.FsmInstance) *UpfHttpServer {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	p := new(UpfHttpServer)
	p.FsmInstance = fsm
	//ip:=utils.GetLocalIp()
	ipPort := configure.CmSysConf.OamIp + ":8892"
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "UpfHttpServer is listenning at %s", ipPort)
	p.HttpServer = agent.CreatehttpServer(ipPort)

	p.RegisterURLHandler("/hello", hello)
	p.RegisterURLHandler("/show", show)
	p.RegisterURLHandler("/usertrace", agent.UserTrace)
	p.RegisterURLHandler("/showusertrace", agent.ShowUserTrace)
	p.RegisterURLHandler("/nfom/v1/config/params/UpfList", jwt.MiddlewareHandler(show))

	//UPF DnnInfo URL
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/DnnInfo/edit", jwt.MiddlewareHandler(p.UpfSettingDnnInfoedit))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/DnnInfo/add", jwt.MiddlewareHandler(p.UpfSettingDnnInfoAdd))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/DnnInfo/delete", jwt.MiddlewareHandler(p.UpfSettingDnnInfoDelete))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/DnnInfo/list", jwt.MiddlewareHandler(p.UpfSettingDnnInfoGetData))
	//UPF PacketCapture URL
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/PacketCapture/edit", jwt.MiddlewareHandler(p.UpfSettingPacketCaptureEdit))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/PacketCapture/add", jwt.MiddlewareHandler(p.UpfSettingPacketCaptureAdd))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/PacketCapture/delete", jwt.MiddlewareHandler(p.UpfSettingPacketCaptureDelete))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/PacketCapture/list", jwt.MiddlewareHandler(p.UpfSettingPacketCaptureGetData))
	//UpfSelection URL
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/UpfSelection/edit", jwt.MiddlewareHandler(p.UpfSettingUpfSelectionedit))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/UpfSelection/add", jwt.MiddlewareHandler(p.UpfSettingUpfSelectionAdd))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/UpfSelection/delete", jwt.MiddlewareHandler(p.UpfSettingUpfSelectionDelete))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/UpfSelection/list", jwt.MiddlewareHandler(p.UpfSettingUpfSelectionGetData))

	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL, jwt.MiddlewareHandler(p.UpfSettingTask))
	p.RegisterURLHandler(webTypes.AGENT_INQUIRY_URL, jwt.MiddlewareHandler(p.UpfInquiryTask))
	p.RegisterURLHandler(webTypes.AGENT_INQUIRY_URL+"/data", jwt.MiddlewareHandler(p.UpfInquiryTasks))
	p.RegisterURLHandler(webTypes.AGENT_ALARM_URL, jwt.MiddlewareHandler(p.UpfGetAlaramActionTask))
	p.RegisterURLHandler(webTypes.AGENT_RESPREG_URL, jwt.MiddlewareHandler(p.UpfRespPegTask))
	//p.RegisterURLHandler(webTypes.AGENT_LOG_URL, p.UpfLoginTask)

	//p.RegisterURLHandler(webTypes.AGENT_RPC_REQUEST_URL, p.RunCommandTask)
	p.RegisterURLHandler(webTypes.AGENT_DIAGNOSIS_URL, jwt.MiddlewareHandler(UpfPerformDiagnosis))
	p.RegisterURLHandler(webTypes.AGENT_SETTING_URL+"/nicname", jwt.MiddlewareHandler(p.UpfSettingNicName))

	//dump packet
	p.RegisterURLHandler(webTypes.AGENT_DUMPPPACKET_URL+"/getallkey", jwt.MiddlewareHandler(p.GetAllKey))
	p.RegisterURLHandler(webTypes.AGENT_DUMPPPACKET_URL+"/setting", jwt.MiddlewareHandler(p.SettingDumpPacket))
	p.RegisterURLHandler(webTypes.AGENT_DUMPPPACKET_URL+"/start", jwt.MiddlewareHandler(p.StartDumpPacket))
	p.RegisterURLHandler(webTypes.AGENT_DUMPPPACKET_URL+"/stop", jwt.MiddlewareHandler(p.StopDumpPacket))
	//download packet
	p.RegisterURLHandler(webTypes.AGENT_DUMPPPACKET_URL+"/getall", jwt.MiddlewareHandler(p.GetAllPacketFiles))
	p.RegisterURLHandler(webTypes.AGENT_DUMPPPACKET_URL+"/download", jwt.MiddlewareHandler(p.DownloadCaptureFile))
	p.RegisterURLHandler(webTypes.AGENT_DUMPPPACKET_URL+"/delete", jwt.MiddlewareHandler(p.DeletePacketFile))
	return p
}

func (p *UpfHttpServer) UpfInquiryTasks(w http.ResponseWriter, req *http.Request) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	var reqData webTypes.ParamsInquireReqData
	resp := webTypes.ParamResponData{200, "successful", nil}
	err := agent.ParseReqData(req, &reqData)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
	}
	for _, param := range reqData.IDs {
		paramId, err := strconv.Atoi(param)
		if err != nil {
			logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		}
		switch paramId {
		case webTypes.UpfSessionSeid:
			integer, err := strconv.Atoi(reqData.Group)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
			}
			Seid, err := oamagent.ShowUpfSessionSeid(uint64(integer))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				resp := webTypes.ParamResponData{500, "Failed to query data", err.Error()}
				agent.RespData(w, resp)
				continue
			}
			resp.Params = Seid
			agent.RespData(w, resp)
			continue
		case webTypes.UpfSessionIp:
			ip, err := oamagent.ShowUpfSessionIp(reqData.Group)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				resp := webTypes.ParamResponData{500, "Failed to query data", err.Error()}
				agent.RespData(w, resp)
				continue
			}
			resp.Params = ip
			agent.RespData(w, resp)
			continue
		case webTypes.UpfSessionTied:
			integer, err := strconv.Atoi(reqData.Group)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
			}
			tied, err := oamagent.ShowUpfSessionTeid(uint32(integer))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				resp := webTypes.ParamResponData{500, "Failed to query data", err.Error()}
				agent.RespData(w, resp)
				continue
			}
			resp.Params = tied
			agent.RespData(w, resp)
			continue
		}
	}
}

func UpfPerformDiagnosis(w http.ResponseWriter, req *http.Request) {
	var reqData = webTypes.NfPmInquireReqData{}
	agent.ParseReqData(req, &reqData)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, reqData)
	//buried point here
	resp := metrics.UpfDiagnosis(reqData, UpfNfName)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, resp)
	agent.RespSettingSuccess(w, "successful", resp)
}

func hello(w http.ResponseWriter, req *http.Request) {
	fmt.Println(req.URL.Path)
	var reqData webTypes.ParamsInquireReqData
	agent.ParseReqData(req, &reqData)
	fmt.Printf("%+v\n", reqData)
	if reqData.IDs[0] == "upf" {
		fmt.Printf("%+v\n", configure.CmUpfConf)
	}
	resp := webTypes.ParamsSettingRespData{0, "successful", nil}
	agent.RespData(w, resp)
}

func show(w http.ResponseWriter, req *http.Request) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)

	var reqData webTypes.ParamsInquireReqData
	err := agent.ParseReqData(req, &reqData)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
	}
	w.Header().Set("content-Type", "application=json")
	agent.RespSettingSuccess(w, "successful", configure.CmUpfConf)
}

func (p *UpfHttpServer) UpfSettingTask(w http.ResponseWriter, req *http.Request) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	flag := 0
	data := configure.CmUpfConf
	var original webTypes.Original
	//host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	host := req.Header.Get("X-Real-Ip")
	datan3 := configure.CmUpfConf.IpConf.N3
	var reqData webTypes.ParamsSettingReqData
	var tempParam webTypes.ParamResp
	resp := webTypes.ParamsSettingRespData{200, "successful", nil}

	err := agent.ParseReqData(req, &reqData)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		goto _fail
	}
	for _, param := range reqData.Params {
		paramId := param.ParamId
		paramValue := param.ParamValue

		switch paramId {
		case webTypes.UPFSESSIONSEID:
			integer, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespData(w, err)
				return
			}
			Seid, err := oamagent.ShowUpfSessionSeid(uint64(integer))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespData(w, err)
				return
			}
			agent.RespData(w, Seid)
			return
		case webTypes.UPFSESSIONTEID:
			integer, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespData(w, err)
				return
			}
			teid, err := oamagent.ShowUpfSessionTeid(uint32(integer))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespData(w, err)
				return
			}
			agent.RespData(w, teid)
			return
		case webTypes.PFCP:
			str := strings.Split(paramValue.(string), ":")
			if len(str) != 2 {
				agent.RespData(w, oamagent.PfcfUpfParam())
				return
			}
			err := cmd.ValidateFeatureUpf(str[0])
			if err != nil {
				agent.RespData(w, oamagent.UpfPfcpValidate())
				return
			}
			bo, err := cmd.OnoffTransition(str[1])
			if err != nil {
				agent.RespData(w, oamagent.UpfPfcpSwitch())
				return
			}
			marshal := oamagent.SetUpfPfcpFeature(str[0], bo)
			agent.RespData(w, marshal)
			return
		case webTypes.UPFVerMain:
			tempParam.ParamId = webTypes.UPFVerMain
			tempParam.ErrorNo = 0
			configure.CmUpfConf.Version.Main = paramValue.(string)
			configure.UpfConf.Version.Main = paramValue.(string)
		case webTypes.UPFVerPatch:
			tempParam.ParamId = webTypes.UPFVerPatch
			tempParam.ErrorNo = 0
			configure.CmUpfConf.Version.Patch = paramValue.(string)
			configure.UpfConf.Version.Patch = paramValue.(string)
		case webTypes.UPFLoggerLevel:
			tempParam.ParamId = webTypes.UPFLoggerLevel
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFLoggerLevel, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.Logger.Level = paramValue.(string)
			configure.UpfConf.Logger.Level = paramValue.(string)
			logger.Initialize(logger.LogConf{
				Ctrl:   configure.UpfConf.Logger.Control,
				Level:  configure.UpfConf.Logger.Level,
				Path:   configure.UpfConf.Logger.Path,
				Topic:  configure.UpfConf.Logger.Topic,
				IpPort: configure.SysConf.KafkaAddr,
			})
		case webTypes.UPFLoggerPath:
			tempParam.ParamId = webTypes.UPFLoggerPath
			tempParam.ErrorNo = 0
			configure.CmUpfConf.Logger.Path = paramValue.(string)
			configure.UpfConf.Logger.Path = paramValue.(string)
			logger.Initialize(logger.LogConf{
				Ctrl:   configure.UpfConf.Logger.Control,
				Level:  configure.UpfConf.Logger.Level,
				Path:   configure.UpfConf.Logger.Path,
				Topic:  configure.UpfConf.Logger.Topic,
				IpPort: configure.SysConf.KafkaAddr,
			})
			nff.NffLogReset()
		case webTypes.UPFLoggerTopic:
			tempParam.ParamId = webTypes.UPFLoggerTopic
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFLoggerTopic, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.Logger.Topic = paramValue.(string)
			configure.UpfConf.Logger.Topic = paramValue.(string)
			logger.Initialize(logger.LogConf{
				Ctrl:   configure.UpfConf.Logger.Control,
				Level:  configure.UpfConf.Logger.Level,
				Path:   configure.UpfConf.Logger.Path,
				Topic:  configure.UpfConf.Logger.Topic,
				IpPort: configure.SysConf.KafkaAddr,
			})
			original.OldData = data.Logger
			original.NewData = configure.CmUpfConf.Logger
			agent.OperationLogs(host, "UPF", "modify configure upf logger", original)
		case webTypes.UPFLoggerControl:
			tempParam.ParamId = webTypes.UPFLoggerControl
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFLoggerControl, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			configure.CmUpfConf.Logger.Control = int8(atoi)
			configure.UpfConf.Logger.Control = int8(atoi)
			logger.Initialize(logger.LogConf{
				Ctrl:   configure.UpfConf.Logger.Control,
				Level:  configure.UpfConf.Logger.Level,
				Path:   configure.UpfConf.Logger.Path,
				Topic:  configure.UpfConf.Logger.Topic,
				IpPort: configure.SysConf.KafkaAddr,
			})
		case webTypes.UPFN3PortId:
			tempParam.ParamId = webTypes.UPFN3PortId
			tempParam.ErrorNo = 0
			flag = 1
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN3PortId, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			_, err = strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			configure.CmUpfConf.IpConf.N3.PortId = 0
			configure.UpfConf.N3.PortId = 0
		case webTypes.UPFN3Ipv4:
			tempParam.ParamId = webTypes.UPFN3Ipv4
			tempParam.ErrorNo = 0
			flag = 1
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN3Ipv4, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			//if len(configure.CmUpfConf.NicName) == 1 {
			//	if paramValue.(string) == configure.CmUpfConf.IpConf.N6.Ipv4 {
			//		configure.CmUpfConf.IpConf.N3.Ipv4 = paramValue.(string)
			//		configure.UpfConf.N3.Ipv4 = paramValue.(string)
			//	} else {
			//		err := errors.New(" Insufficient network cards ")
			//		agent.RespSettingError(w, err, nil)
			//		return
			//	}
			//} else {
			//	configure.CmUpfConf.IpConf.N3.Ipv4 = paramValue.(string)
			//	configure.UpfConf.N3.Ipv4 = paramValue.(string)
			//}
			//if paramValue.(string) == configure.CmUpfConf.IpConf.N3.Ipv6 && configure.CmUpfConf.IpConf.N3.Ipv4 == configure.UpfConf.N6.Ipv4 {
			//	configure.CmUpfConf.IpConf.N6.PortId = 0
			//	configure.UpfConf.N6.PortId = 0
			//} else {
			//	configure.CmUpfConf.IpConf.N6.PortId = 1
			//	configure.UpfConf.N6.PortId = 1
			//}
			configure.CmUpfConf.IpConf.N3.Ipv4 = paramValue.(string)
			configure.UpfConf.N3.Ipv4 = paramValue.(string)
		case webTypes.UPFN3Mask:
			tempParam.ParamId = webTypes.UPFN3Mask
			tempParam.ErrorNo = 0
			flag = 1
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN3Mask, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.IpConf.N3.Mask = paramValue.(string)
			configure.UpfConf.N3.Mask = paramValue.(string)
		case webTypes.UPFN3Ipv6:
			tempParam.ParamId = webTypes.UPFN3Ipv6
			tempParam.ErrorNo = 0
			if paramValue.(string) != "" {
				err := cmd.ValidateUpfHttpServer(webTypes.UPFN3Ipv6, paramValue.(string))
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					agent.RespSettingError(w, err, []webTypes.ParamResp{})
					return
				}
			}
			configure.CmUpfConf.IpConf.N3.Ipv6 = paramValue.(string)
			configure.UpfConf.N3.Ipv6 = paramValue.(string)
		case webTypes.UPFN3Ipv6Mask:
			tempParam.ParamId = webTypes.UPFN3Ipv6Mask
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN3Ipv6Mask, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.IpConf.N3.Ipv6Mask = paramValue.(string)
			configure.UpfConf.N3.Ipv6Mask = paramValue.(string)
		case webTypes.UPFN4LocalIpv4:
			if !utils.IsLocalIp(paramValue.(string)) {
				logger.Trace(types.ModuleAmfN2Proc, logger.DEBUG, nil, "invalid ip:%s", paramValue.(string))
				resp := webTypes.ParamsSettingRespData{ErrorNo: 500, ErrorMessage: fmt.Sprintf("invalid ip:%s", paramValue.(string))}
				agent.RespData(w, resp)
				return
			}
			tempParam.ParamId = webTypes.UPFN4LocalIpv4
			tempParam.ErrorNo = 0
			flag = 2
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN4LocalIpv4, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.N4.Local.Ipv4 = paramValue.(string)
			configure.UpfConf.N4.Local.Ipv4 = paramValue.(string)
		case webTypes.UPFN4LocalPort:
			tempParam.ParamId = webTypes.UPFN4LocalPort
			tempParam.ErrorNo = 0
			flag = 2
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN4LocalPort, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			configure.CmUpfConf.N4.Local.Port = atoi
			configure.UpfConf.N4.Local.Port = atoi
			original.OldData = data.N4.Local
			original.NewData = configure.CmUpfConf.N4.Local
			agent.OperationLogs(host, "UPF", "modify configure upf n4", original)
		case webTypes.UPFN4SmfIpv4:
			tempParam.ParamId = webTypes.UPFN4SmfIpv4
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN4SmfIpv4, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.N4.Smf.Ipv4 = paramValue.(string)
			configure.UpfConf.N4.Smf.Ipv4 = paramValue.(string)
		case webTypes.UPFN4SmfPort:
			tempParam.ParamId = webTypes.UPFN4SmfPort
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN4SmfPort, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			configure.CmUpfConf.N4.Smf.Port = atoi
			configure.UpfConf.N4.Smf.Port = atoi
		case webTypes.UPFN6PortId:
			tempParam.ParamId = webTypes.UPFN6PortId
			tempParam.ErrorNo = 0
			flag = 3
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN6PortId, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			_, err = strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			if configure.CmUpfConf.IpConf.N3.Ipv4 == configure.CmUpfConf.IpConf.N6.Ipv4 && configure.CmUpfConf.IpConf.N3.Ipv6 == configure.CmUpfConf.IpConf.N6.Ipv6 {
				configure.CmUpfConf.IpConf.N6.PortId = 0
				configure.UpfConf.N6.PortId = 0
			} else {
				configure.CmUpfConf.IpConf.N6.PortId = 1
				configure.UpfConf.N6.PortId = 1
			}
		case webTypes.UPFN6Ipv4:
			tempParam.ParamId = webTypes.UPFN6Ipv4
			tempParam.ErrorNo = 0
			flag = 3
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN6Ipv4, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			if len(configure.CmUpfConf.NicName) == 1 {
				if paramValue.(string) == configure.CmUpfConf.IpConf.N3.Ipv4 {
					configure.CmUpfConf.IpConf.N6.Ipv4 = paramValue.(string)
					configure.UpfConf.N6.Ipv4 = paramValue.(string)
				} else {
					configure.CmUpfConf.IpConf.N3.Ipv4 = datan3.Ipv4
					configure.CmUpfConf.IpConf.N3.Ipv6 = datan3.Ipv6
					err := errors.New(" Insufficient network cards ")
					agent.RespSettingError(w, err, nil)
					return
				}
			} else {
				configure.CmUpfConf.IpConf.N6.Ipv4 = paramValue.(string)
				configure.UpfConf.N6.Ipv4 = paramValue.(string)
			}
			if paramValue.(string) == configure.CmUpfConf.IpConf.N3.Ipv4 && configure.CmUpfConf.IpConf.N3.Ipv6 == configure.CmUpfConf.IpConf.N6.Ipv6 {
				configure.CmUpfConf.IpConf.N6.PortId = 0
				configure.UpfConf.N6.PortId = 0
			} else {
				configure.CmUpfConf.IpConf.N6.PortId = 1
				configure.UpfConf.N6.PortId = 1
			}
		case webTypes.UPFN6Mask:
			tempParam.ParamId = webTypes.UPFN6Mask
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN6Mask, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.IpConf.N6.Mask = paramValue.(string)
			configure.UpfConf.N6.Mask = paramValue.(string)
		case webTypes.UPFN6Ipv6:
			tempParam.ParamId = webTypes.UPFN6Ipv6
			tempParam.ErrorNo = 0
			if paramValue.(string) != "" {
				err := cmd.ValidateUpfHttpServer(webTypes.UPFN6Ipv6, paramValue.(string))
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					agent.RespSettingError(w, err, []webTypes.ParamResp{})
					return
				}
			}
			if len(configure.CmUpfConf.NicName) == 1 {
				if paramValue.(string) == configure.CmUpfConf.IpConf.N3.Ipv6 {
					configure.CmUpfConf.IpConf.N6.Ipv6 = paramValue.(string)
					configure.UpfConf.N6.Ipv6 = paramValue.(string)
				} else {
					configure.CmUpfConf.IpConf.N3.Ipv4 = datan3.Ipv4
					configure.CmUpfConf.IpConf.N3.Ipv6 = datan3.Ipv6
					err := errors.New(" Insufficient network cards ")
					agent.RespSettingError(w, err, nil)
					return
				}
			} else {
				configure.CmUpfConf.IpConf.N6.Ipv6 = paramValue.(string)
				configure.UpfConf.N6.Ipv6 = paramValue.(string)
			}
			if paramValue.(string) == configure.CmUpfConf.IpConf.N3.Ipv6 && configure.CmUpfConf.IpConf.N3.Ipv4 == configure.UpfConf.N6.Ipv4 {
				configure.CmUpfConf.IpConf.N6.PortId = 0
				configure.UpfConf.N6.PortId = 0
			} else {
				configure.CmUpfConf.IpConf.N6.PortId = 1
				configure.UpfConf.N6.PortId = 1
			}
			original.OldData = data.IpConf
			original.NewData = configure.CmUpfConf.IpConf
			agent.OperationLogs(host, "UPF", "modify configure upf IPconf", original)
		case webTypes.UPFNffDbdkArgs:
			tempParam.ParamId = webTypes.UPFNffDbdkArgs
			tempParam.ErrorNo = 0
			configure.CmUpfConf.Nff.DpdkArgs = paramValue.(string)
			configure.UpfConf.Nff.DpdkArgs = paramValue.(string)
		case webTypes.UPFNffCpuLIst:
			tempParam.ParamId = webTypes.UPFNffCpuLIst
			tempParam.ErrorNo = 0
			configure.CmUpfConf.Nff.CpuList = paramValue.(string)
			configure.UpfConf.Nff.CpuList = paramValue.(string)
		case webTypes.UPFNffMaxNumber:
			tempParam.ParamId = webTypes.UPFNffMaxNumber
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFNffMaxNumber, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			configure.CmUpfConf.Nff.MaxInstanceNum = atoi
			configure.UpfConf.Nff.MaxInstanceNum = atoi
		case webTypes.UPFNffUseVector:
			tempParam.ParamId = webTypes.UPFNffUseVector
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFNffUseVector, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			if paramValue.(string) == "true" {
				configure.CmUpfConf.Nff.UseVector = true
				configure.UpfConf.Nff.UseVector = true
			} else {
				configure.CmUpfConf.Nff.UseVector = false
				configure.UpfConf.Nff.UseVector = false
			}
		case webTypes.UPFNffStaSerNostats:
			tempParam.ParamId = webTypes.UPFNffStaSerNostats
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFNffStaSerNostats, paramValue.(string))
			fmt.Println(err)
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			if paramValue.(string) == "true" {
				configure.CmUpfConf.Nff.StatsServerNostats = true
				configure.UpfConf.Nff.StatsServerNostats = true
			} else {
				configure.CmUpfConf.Nff.StatsServerNostats = false
				configure.UpfConf.Nff.StatsServerNostats = false
			}
		case webTypes.UPFNffStaSerAddress:
			tempParam.ParamId = webTypes.UPFNffStaSerAddress
			tempParam.ErrorNo = 0
			configure.CmUpfConf.Nff.StatsServerAddress = paramValue.(string)
			configure.UpfConf.Nff.StatsServerAddress = paramValue.(string)
		case webTypes.UPFNffStaSerPort:
			tempParam.ParamId = webTypes.UPFNffStaSerPort
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFNffStaSerPort, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			configure.CmUpfConf.Nff.StatsServerPort = atoi
			configure.UpfConf.Nff.StatsServerPort = atoi
		case webTypes.UPFPmStartModuleCount:
			tempParam.ParamId = webTypes.UPFPmStartModuleCount
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFPmStartModuleCount, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			if paramValue.(string) == "true" {
				configure.CmUpfConf.Pm.Startmodulecount = true
				configure.UpfConf.Pm.Startmodulecount = true
				metrics.ModuleCounterStart = true
			} else {
				configure.CmUpfConf.Pm.Startmodulecount = false
				configure.UpfConf.Pm.Startmodulecount = false
				metrics.ModuleCounterStart = false
			}
		case webTypes.UPFPmStartSessionCount:
			tempParam.ParamId = webTypes.UPFPmStartSessionCount
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFPmStartSessionCount, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			if paramValue.(string) == "true" {
				configure.CmUpfConf.Pm.Startsessioncount = true
				configure.UpfConf.Pm.Startsessioncount = true
				metrics.SessionCounterStart = true
			} else {
				configure.CmUpfConf.Pm.Startsessioncount = false
				configure.UpfConf.Pm.Startsessioncount = false
				metrics.SessionCounterStart = false
			}
			original.OldData = data.Pm
			original.NewData = configure.CmUpfConf.Pm
			agent.OperationLogs(host, "UPF", "modify configure upf pm", original)
		case webTypes.UPFTimerPfcpt1:
			tempParam.ParamId = webTypes.UPFTimerPfcpt1
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFTimerPfcpt1, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				return
			}
			configure.CmUpfConf.Timer.Pfcpt1 = atoi
			configure.UpfConf.Timer.Pfcpt1 = atoi
		case webTypes.UPFTimerGtput1:
			tempParam.ParamId = webTypes.UPFTimerGtput1
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFTimerGtput1, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				return
			}
			configure.CmUpfConf.Timer.Gtput1 = atoi
			configure.UpfConf.Timer.Gtput1 = atoi
			original.OldData = data.Timer
			original.NewData = configure.CmUpfConf.Timer
			agent.OperationLogs(host, "UPF", "modify configure upf timer", original)
		case webTypes.UPFN3Gateway:
			tempParam.ParamId = webTypes.UPFN3Gateway
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFN3Gateway, paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.IpConf.N3.Gateway = paramValue.(string)
			configure.UpfConf.N3.Gateway = paramValue.(string)
			original.OldData = data.IpConf.N3.Gateway
			original.NewData = configure.CmUpfConf.IpConf.N3.Gateway
		case webTypes.UPFN6Ipv4Gateway:
			tempParam.ParamId = webTypes.UPFN6Ipv4Gateway
			tempParam.ErrorNo = 0
			configure.CmUpfConf.IpConf.N6.Gateway = paramValue.(string)
			configure.UpfConf.N6.Gateway = paramValue.(string)
		case webTypes.UPFN6Ipv6Gateway:
			tempParam.ParamId = webTypes.UPFN6Ipv6Gateway
			tempParam.ErrorNo = 0
			configure.CmUpfConf.IpConf.N6.Ipv6Gw = paramValue.(string)
			configure.UpfConf.N6.Ipv6Gw = paramValue.(string)
		case webTypes.UPFN6Ipv4Mask:
			tempParam.ParamId = webTypes.UPFN6Ipv4Mask
			tempParam.ErrorNo = 0
			configure.CmUpfConf.IpConf.N6.Mask = paramValue.(string)
			configure.UpfConf.N6.Mask = paramValue.(string)
		case webTypes.UPFN6Ipv6Mask:
			tempParam.ParamId = webTypes.UPFN6Ipv6Mask
			tempParam.ErrorNo = 0
			configure.CmUpfConf.IpConf.N6.Ipv6Mask = paramValue.(string)
			configure.UpfConf.N6.Ipv6Mask = paramValue.(string)
		case webTypes.UPFKernel:
			tempParam.ParamId = webTypes.UPFKernel
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFKernel, paramValue.(string))
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			if paramValue.(string) == "true" {
				configure.CmUpfConf.Kernel = true
				configure.UpfConf.Kernel = true
			} else {
				configure.CmUpfConf.Kernel = false
				configure.UpfConf.Kernel = false
			}
		case webTypes.UPFHugePageType:
			tempParam.ParamId = webTypes.UPFHugePageType
			tempParam.ErrorNo = 0
			configure.CmUpfConf.HugePage.NumaType = paramValue.(string)
			configure.UpfConf.HugePage.NumaType = paramValue.(string)
		case webTypes.UPFHugePageNum:
			tempParam.ParamId = webTypes.UPFHugePageNum
			tempParam.ErrorNo = 0
			atoi, err := strconv.Atoi(paramValue.(string))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				agent.RespSettingError(w, err, nil)
				return
			}
			err1 := cmd.ValidateHuge(atoi)
			if err1 != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err1)
				agent.RespSettingError(w, err1, nil)
				return
			}
			configure.CmUpfConf.HugePage.PageNum = atoi
			configure.UpfConf.HugePage.PageNum = atoi
			flag = 5
		case webTypes.UPFSbiUpfIp:
			tempParam.ParamId = webTypes.UPFSbiUpfIp
			tempParam.ErrorNo = 0
			flag = webTypes.UPFSbiUpfIp
			err := cmd.ValidateUpfHttpServer(webTypes.UPFSbiUpfIp, paramValue.(string))
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.Sbi.Upf.Addr.Ip = paramValue.(string)
			configure.UpfConf.Sbi.Upf.Addr.Ip = paramValue.(string)
			err = sbiupf.SbiUpfRestart()
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				goto _fail
			}
		case webTypes.UPFSbiUpfPort:
			tempParam.ParamId = webTypes.UPFSbiUpfPort
			tempParam.ErrorNo = 0
			flag = webTypes.UPFSbiUpfPort
			err := cmd.ValidateUpfHttpServer(webTypes.UPFSbiUpfPort, paramValue.(string))
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, _ := strconv.Atoi(paramValue.(string))
			configure.CmUpfConf.Sbi.Upf.Addr.Port = atoi
			configure.UpfConf.Sbi.Upf.Addr.Port = atoi
			err = sbiupf.SbiUpfRestart()
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				goto _fail
			}
		case webTypes.UPFSbiUpfScheme:
			tempParam.ParamId = webTypes.UPFSbiUpfScheme
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFSbiUpfScheme, paramValue.(string))
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.Sbi.Upf.Scheme = paramValue.(string)
			configure.UpfConf.Sbi.Upf.Scheme = paramValue.(string)
			original.OldData = data.Sbi.Upf
			original.NewData = configure.CmUpfConf.Sbi.Upf
			err = sbiupf.SbiUpfRestart()
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				goto _fail
			}
			agent.OperationLogs(host, "UPF", "modify configure upf sbiupf", original)
		case webTypes.UPFService:
			tempParam.ParamId = webTypes.UPFService
			tempParam.ErrorNo = 0
			flag = webTypes.UPFService
			configure.CmUpfConf.Service.InstanceId = paramValue.(string)
			configure.UpfConf.Service.InstanceId = paramValue.(string)
		case webTypes.UPFSbiNrfIp:
			tempParam.ParamId = webTypes.UPFSbiNrfIp
			tempParam.ErrorNo = 0
			flag = webTypes.UPFSbiNrfIp
			err := cmd.ValidateUpfHttpServer(webTypes.UPFSbiNrfIp, paramValue.(string))
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.Sbi.Nrf.Addr.Ip = paramValue.(string)
			configure.UpfConf.Sbi.Nrf.Addr.Ip = paramValue.(string)
			//nfctxt.NRFRestart()
		case webTypes.UPFSbiNrfPort:
			tempParam.ParamId = webTypes.UPFSbiNrfPort
			tempParam.ErrorNo = 0
			flag = webTypes.UPFSbiNrfPort
			err := cmd.ValidateUpfHttpServer(webTypes.UPFSbiNrfPort, paramValue.(string))
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			atoi, _ := strconv.Atoi(paramValue.(string))
			configure.CmUpfConf.Sbi.Nrf.Addr.Port = atoi
			configure.UpfConf.Sbi.Nrf.Addr.Port = atoi
			//nfctxt.NRFRestart()
		case webTypes.UPFSbiNrfScheme:
			tempParam.ParamId = webTypes.UPFSbiNrfScheme
			tempParam.ErrorNo = 0
			err := cmd.ValidateUpfHttpServer(webTypes.UPFSbiNrfScheme, paramValue.(string))
			if err != nil {
				agent.RespSettingError(w, err, []webTypes.ParamResp{})
				return
			}
			configure.CmUpfConf.Sbi.Nrf.Scheme = paramValue.(string)
			configure.UpfConf.Sbi.Nrf.Scheme = paramValue.(string)
			original.OldData = data.Sbi.Nrf
			original.NewData = configure.CmUpfConf.Sbi.Nrf
			//nfctxt.NRFRestart()
			agent.OperationLogs(host, "UPF", "modify configure upf  sbinrf", original)
		}
		resp.Params = append(resp.Params, tempParam)
	}
	//yaml.Dump(configure.CmUpfConf, types.DefConfFileUpf)
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "UpfSettingTask handle success")
	agent.RespData(w, resp)

	agent.TakeEffectUpfConf(flag)
	//agent.TakeEffectconf("upf", flag)

	//The modified configuration has been loaded into the configure file and can be reloaded
	go func() {
		if flag == 5 {
			err := envinit.SetHugePages(configure.UpfConf.HugePage.NumaType, configure.UpfConf.HugePage.PageNum)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.WARN, nil, err)
			}
			dealsAfterConfigDpdkEnv()
		}
	}()

	return

_fail:
	logger.Trace(types.ModuleAmfAgent, logger.ERROR, nil, err)
	agent.RespData(w, webTypes.ParamsSettingRespData{0, err.Error(), nil})
}

func dealsAfterConfigDpdkEnv() {
	if envinit.NicBindResultInfo == nil {
		os.Exit(1)
	} else {
		if err := envinit.RecoverNicEnv(envinit.NicBindResultInfo.DevInfo, envinit.NicBindResultInfo.DriverStr); err != nil {
			rlogger.Trace(types.ModuleUpfAgent, rlogger.WARN, nil, "Recover Nic Env Failed!")
		}
		os.Exit(1)
	}
}

// setting nic  name
func (p *UpfHttpServer) UpfSettingNicName(w http.ResponseWriter, req *http.Request) {
	var data []string
	conf := configure.CmUpfConf
	var original webTypes.Original
	host, _, _ := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))

	err := agent.ParseReqData(req, &data)
	fmt.Printf("NicName:%v\n", data)

	if err != nil {
		logger.Trace(types.ModuleSmfAgent, logger.ERROR, nil, err)
		return
	}
	if len(data) == 1 {
		if configure.CmUpfConf.IpConf.N3.Ipv4 == configure.CmUpfConf.IpConf.N6.Ipv4 && configure.CmUpfConf.IpConf.N3.Ipv6 == configure.CmUpfConf.IpConf.N6.Ipv6 {
			configure.CmUpfConf.NicName = data
			configure.UpfConf.NicName = data
		} else {
			err := errors.New("please confirm n3 n6 ipv4 are consistent")
			agent.RespSettingError(w, err, nil)
			return
		}
	} else {

		configure.CmUpfConf.NicName = data
		configure.UpfConf.NicName = data
	}
	agent.RespSettingSuccess(w, "successful", data)
	yaml.Dump(configure.CmUpfConf, types.DefConfFileUpf)

	original.OldData = conf.NicName
	original.NewData = configure.CmUpfConf.NicName
	agent.OperationLogs(host, "UPF", "modify upf nicname configure", original)

	go dealsAfterConfigDpdkEnv()
	return
}

func (p *UpfHttpServer) UpfInquiryTask(w http.ResponseWriter, req *http.Request) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err) //
			str := fmt.Sprintf("Failed ! Error(%v)", err)
			resp := webTypes.ParamsSettingRespData{500, str, nil}
			agent.RespData(w, resp)
			logger.Trace(types.ModuleAmfAgent, logger.DEBUG, nil, resp)
		}
	}()

	var reqData webTypes.ParamsInquireReqData
	var tempParam webTypes.Param
	resp := webTypes.ParamsInquireRespData{0, "successful", nil}

	err := agent.ParseReqData(req, &reqData)
	//fmt.Println("req:", reqData)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		goto _fail
	}
	//if reqData.Group!=""{
	//	logger.Trace(types.ModuleUpfAgent,logger.ERROR,nil,"UpfInquiryTask not support inquire params by group")
	//}else{
	fmt.Println(reqData.Group)
	for _, param := range reqData.IDs {
		paramId, err := strconv.Atoi(param)
		if err != nil {
			logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
			goto _fail
		}
		switch paramId {
		case webTypes.Conf:
			tempParam.ParamId = webTypes.Conf
			marshal, err := json.Marshal(configure.CmUpfConf)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFHugePage:
			tempParam.ParamId = webTypes.UPFHugePage
			marshal, err := json.Marshal(configure.CmUpfConf.HugePage)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFNic:
			tempParam.ParamId = webTypes.UPFNic
			marshal, err := json.Marshal(configure.CmUpfConf.NicName)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFSbi:
			tempParam.ParamId = webTypes.UPFSbi
			marshal, err := json.Marshal(configure.CmUpfConf.Sbi)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFSelection:
			tempParam.ParamId = webTypes.UPFSelection
			marshal, err := json.Marshal(configure.CmUpfConf.UpfSel)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UpfSessionSeid:
			tempParam.ParamId = webTypes.UpfSessionSeid
			if reqData.Group == "" {
				marshal, err := json.Marshal(oamagent.UpfSeidHint())
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					goto _fail
				}
				tempParam.ParamValue = string(marshal)
				resp.Params = append(resp.Params, tempParam)
				continue
			}
			integer, err := strconv.Atoi(reqData.Group)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			Seid, err := oamagent.ShowUpfSessionSeid(uint64(integer))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			marshal, err := json.Marshal(Seid)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UpfSessionIp:
			tempParam.ParamId = webTypes.UpfSessionIp
			if reqData.Group == "" {
				marshal, err := json.Marshal(oamagent.UpfIpHint())
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					goto _fail
				}
				tempParam.ParamValue = string(marshal)
				resp.Params = append(resp.Params, tempParam)
				continue
			}
			ip, err := oamagent.ShowUpfSessionIp(reqData.Group)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			marshal, err := json.Marshal(ip)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UpfSessionTied:
			tempParam.ParamId = webTypes.UpfSessionTied
			if reqData.Group == "" {
				marshal, err := json.Marshal(oamagent.UpfTiedHint())
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					goto _fail
				}
				tempParam.ParamValue = string(marshal)
				resp.Params = append(resp.Params, tempParam)
				continue
			}
			integer, err := strconv.Atoi(reqData.Group)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tied, err := oamagent.ShowUpfSessionTeid(uint32(integer))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			marshal, err := json.Marshal(tied)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UpfArpTable:
			tempParam.ParamId = webTypes.UpfArpTable
			str, err := oamagent.ShowUpfArpTable()
			if err != nil {
				fmt.Println(err)
			}
			//fmt.Println("upfarptable=:", str)
			marshal, err := json.Marshal(str)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UpfContextN3:
			tempParam.ParamId = webTypes.UpfContextN3
			str, err := oamagent.ShowUpfContextN3()
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
			}
			//fmt.Println("contextn3=:", str)
			marshal, err := json.Marshal(str)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UpfContextN6:
			tempParam.ParamId = webTypes.UpfContextN6
			str, err := oamagent.ShowUpfContextN6()
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
			}
			//fmt.Println("contextn6=:", str)
			Marshal, err := json.Marshal(str)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(Marshal)
		case webTypes.Pfcp:
			tempParam.ParamId = webTypes.Pfcp
			if reqData.Group == "" {
				marshal, err := json.Marshal(oamagent.PfcfUpfParam())
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					goto _fail
				}
				tempParam.ParamValue = string(marshal)
				resp.Params = append(resp.Params, tempParam)
				continue
			}
			str := strings.Split(reqData.Group, ":")
			if len(str) != 2 {
				marshal, err := json.Marshal(oamagent.PfcfUpfParam())
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					goto _fail
				}
				tempParam.ParamValue = string(marshal)
				resp.Params = append(resp.Params, tempParam)
				continue
			}
			err := cmd.ValidateFeatureUpf(str[0])
			if err != nil {
				marshal, err := json.Marshal(oamagent.UpfPfcpValidate())
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					goto _fail
				}
				tempParam.ParamValue = string(marshal)
				resp.Params = append(resp.Params, tempParam)
				continue
			}
			bo, err := cmd.OnoffTransition(str[1])
			if err != nil {
				marshal, err := json.Marshal(oamagent.UpfPfcpSwitch())
				if err != nil {
					logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
					goto _fail
				}
				tempParam.ParamValue = string(marshal)
				resp.Params = append(resp.Params, tempParam)
				continue
			}
			marshal, err := json.Marshal(oamagent.SetUpfPfcpFeature(str[0], bo))
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.HELP:
			tempParam.ParamId = webTypes.HELP
			marshal, err := json.Marshal(oamagent.UpfHelp())
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.PfcpHelp:
			tempParam.ParamId = webTypes.PfcpHelp
			marshal, err := json.Marshal(oamagent.HintUpfPfcp())
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.Version:
			tempParam.ParamId = webTypes.Version
			marshal, err := json.Marshal(configure.CmUpfConf.Version)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.Logger:
			marshal, err := json.Marshal(configure.CmUpfConf.Logger)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFPacketCapture:
			tempParam.ParamId = webTypes.UPFPacketCapture
			marshal, err := json.Marshal(configure.CmUpfConf.PacketCapture)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		//case webTypes.UPFN3:
		//	tempParam.ParamId = webTypes.UPFN3
		//	marshal, err := json.Marshal(configure.CmUpfConf.N3)
		//	if err != nil {
		//		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		//		goto _fail
		//	}
		//	tempParam.ParamValue = string(marshal)
		case webTypes.N4:
			tempParam.ParamId = webTypes.N4
			marshal, err := json.Marshal(configure.CmUpfConf.N4)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		//case webTypes.UPFN6:
		//	tempParam.ParamId = webTypes.UPFN6
		//	marshal, err := json.Marshal(configure.CmUpfConf.N6)
		//	if err != nil {
		//		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
		//		goto _fail
		//	}
		//	tempParam.ParamValue = string(marshal)
		case webTypes.UPFNff:
			tempParam.ParamId = webTypes.UPFNff
			marshal, err := json.Marshal(configure.CmUpfConf.Nff)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFDnnInfo:
			tempParam.ParamId = webTypes.UPFDnnInfo
			marshal, err := json.Marshal(configure.CmUpfConf.DnnInfo)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFN3Gateway:
			tempParam.ParamId = webTypes.UPFN3Gateway
			marshal, err := json.Marshal(configure.CmUpfConf.IpConf.N3.Gateway)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.Timer:
			tempParam.ParamId = webTypes.Timer
			marshal, err := json.Marshal(configure.UpfConf.Timer)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		case webTypes.UPFPm:
			tempParam.ParamId = webTypes.UPFPm
			marshal, err := json.Marshal(configure.CmUpfConf.Pm)
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		default:
			marshal, err := json.Marshal(oamagent.UpfValidateParams())
			if err != nil {
				logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, err)
				goto _fail
			}
			tempParam.ParamValue = string(marshal)
		}
		resp.Params = append(resp.Params, tempParam)

	}

	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "UpfInquiryTask handle success")
	agent.RespData(w, resp)
	return
_fail:
	logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "UpfSettingTask handle fail")
	agent.RespData(w, webTypes.ParamsInquireRespData{0, err.Error(), nil})

}
func (p *UpfHttpServer) UpfGetAlaramActionTask(w http.ResponseWriter, req *http.Request) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)

	agent.RespData(w, webTypes.AlarmRespData{0, "No Error", nil})
}

func (p *UpfHttpServer) UpfRespPegTask(w http.ResponseWriter, req *http.Request) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)

	var reqData webTypes.RegRespData
	err := agent.ParseReqData(req, &reqData)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "UpfRespRegTask handle fail")
		agent.RespData(w, webTypes.RegRespAckData{0, err.Error()})
		return
	}
	logger.Trace(types.ModuleUpfAgent, logger.DEBUG, nil, reqData)
	if UpfNfName == reqData.NfName {
		p.FsmNfNO = reqData.NfNo
		logger.Trace(types.ModuleUpfAgent, logger.DEBUG, nil, "FsmNfNO: %s", p.FsmNfNO)
		logger.Trace(types.ModuleUpfAgent, logger.DEBUG, nil, "before EventRegResp upfFsmInstance.Bfsm: \n%s", p.FsmInstance)
		p.FsmInstance.Bfsm.Event(agent.EventRegResp)
		logger.Trace(types.ModuleUpfAgent, logger.DEBUG, nil, "after EventRegResp upfFsmInstance.Bfsm: \n%s", p.FsmInstance)

		logger.Trace(types.ModuleUpfAgent, logger.ERROR, nil, "UpfRespRegTask handle success")
		agent.RespData(w, webTypes.RegRespAckData{0, "No Error"})
	} else {
		logger.Trace(types.ModuleUpfAgent, logger.ERROR, "nil", "nfname error")
		return
	}
	return
}
