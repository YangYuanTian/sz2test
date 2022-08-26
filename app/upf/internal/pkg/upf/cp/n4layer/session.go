package n4layer

import (
	"container/list"
	"errors"
	"fmt"
	"upf/internal/pkg/cmn/idmgr"
	"upf/internal/pkg/cmn/message/pfcp"
	"upf/internal/pkg/cmn/message/pfcp/utils"
	"upf/internal/pkg/cmn/metric"
	"upf/internal/pkg/cmn/rlogger"
	"upf/internal/pkg/cmn/types"
	"upf/internal/pkg/cmn/types/configure"
	"upf/internal/pkg/cmn/types3gpp"
	utils2 "upf/internal/pkg/cmn/utils"

	"time"
	"upf/internal/pkg/upf/context/n4gtpcontext"

	"net"
	"net/rpc/jsonrpc"
	"strconv"
	"upf/internal/pkg/upf/context/n4context"
	"upf/internal/pkg/upf/context/pdrcontext"
	"upf/internal/pkg/upf/cp/pdr"
	"upf/internal/pkg/upf/metrics"
)

// 3GPP TS 29.244 V15.3.0 (2018-09)
// N4 消息
type N4Msg struct {
}

var DeepCopyTest bool

// 注册N4请求的响应
// N4 Session Release Request
// RPC 中方法名作为消息类型标识，第一个参数是消息的内容，第二个参数是需要返回的响应消息内容。
func (s *N4Msg) SessionReleaseRequest(req pfcp.SessionReleaseRequest,
	res *pfcp.SessionReleaseResponse) (ret error) {

	rlogger.FuncEntry(moduleTag, utils2.Seid(req.PfcpHeader.SEID))

	res.PfcpHeader.Version = pfcp.Version
	res.PfcpHeader.MessageType = pfcp.PFCP_Session_Deletion_Response
	res.PfcpHeader.SEID = 0
	res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
	// 读取当前上下文
	n4Cxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(req.PfcpHeader.SEID))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID), "Failed to get N4 Context:%s", err)
		res.IE.Cause.CauseValue = pfcp.Cause_System_failure
		return nil

	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Success to get N4 context")

	// N4 Session Release Response
	if req.PfcpHeader.MessageType != pfcp.PFCP_Session_Deletion_Request {
		//return errors.New("Session Release Request message type error: " +
		//	strconv.Itoa(int(req.PfcpHeader.MessageType)))
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Message type error:message type should be session release request,rather than type:%+v", req.PfcpHeader.MessageType)
		res.IE.Cause.CauseValue = pfcp.Cause_Service_not_supported
		return nil
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Received session release request:%+v", req.PfcpHeader)
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "MessageType    %v", req.PfcpHeader.MessageType)
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(req.PfcpHeader.SEID), "SEID           %v", req.PfcpHeader.SEID)
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "SequenceNumber %v", req.PfcpHeader.SequenceNumber)

	// todo meter release
	err = metrics.SessionMeterRelease(n4Cxt.MetricItems)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Release upf context counter failed:%s", err)
		//return nil
	} else {
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Success to release session meter")
	}
	err = metrics.SessionMeterRelease(n4Cxt.MetricItemsSnapshot)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Release upf context counter snapshot failed:%s", err)
		//return nil
	} else {
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Success in releasing session meter snapshot")
	}

	//3.	The UPF identifies the N4 session context to be removed by the N4 Session ID and removes the whole session context.
	//The UPF responds with an N4 session release response message containing any information that the UPF has to provide to the SMF.
	// 释放会话,删除上下文
	err = n4context.DeleteN4Context(n4context.N4SessionIDKey(n4Cxt.SEID), n4Cxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Failed to delete N4 context:%s", err)
		res.IE.Cause.CauseValue = pfcp.Cause_Session_context_not_found
	} else {
		res.IE.Cause.CauseValue = pfcp.Cause_Request_accepted
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Success in  deleting N4 context:cause_request_accepted")
	}
	// delete PDR Table
	err = pdr.DeleteMatchPDRsTable(n4Cxt) // 1.1版本更新  DeleteMatchPDRsTable(n4Cxt) // 1.0 版本
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Failed to delete match PDRs table:%s", err)
		res.IE.Cause.CauseValue = pfcp.Cause_Session_context_not_found
	} else {
		res.IE.Cause.CauseValue = pfcp.Cause_Request_accepted
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "success in deleting PDR table:cause_request_accepted")
	}
	res.PfcpHeader.Version = pfcp.Version
	res.PfcpHeader.MPFlag = 0
	res.PfcpHeader.SFlag = 1

	res.PfcpHeader.MessageType = pfcp.PFCP_Session_Deletion_Response
	res.PfcpHeader.SEID = n4Cxt.SmfSEID.SEID
	res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Response packet header :%+v", res.PfcpHeader)
	//res.IE.Cause.Set()
	//res.IE.Cause.CauseValue = pfcp.Cause_Request_accepted
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Release N4 context completed---------------")
	return nil
}

// N4 Session Establishment Request
func (s *N4Msg) SessionEstablishmentRequest(req pfcp.SessionEstablishmentRequest,
	res *pfcp.SessionEstablishmentResponse) error {
	rlogger.FuncEntry(moduleTag, utils2.Seid(req.PfcpHeader.SEID))
	// 收到请求消息处理
	if req.PfcpHeader.MessageType != pfcp.PFCP_Session_Establishment_Request {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID),
			"Message type error,Correct value 50(Session Establishment), Error value is %d", req.PfcpHeader.MessageType)
		return errors.New("Session Establishment Request message type error: " + strconv.Itoa(int(req.PfcpHeader.MessageType)))
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID),
		"Received N4 message:session establishment request:(message type %v,init SEID %v,sequence number %v,smf SEID %v)",
		req.PfcpHeader.MessageType, req.PfcpHeader.SEID, req.PfcpHeader.SequenceNumber, req.IE.CPFSEID.SEID)

	// 添加UPF上下文
	// key生成UPF本地的SEID
	// 保存SMF的SEID
	//用UpfN4Layer.UpfIp作为key由upf生成Teid,下面是除零操作
	idmgr.GetInst().RegisterIDMgr(UpfN4Layer.UpfIp, types.MaxNumSmfTeid)
	err := idmgr.GetInst().ReserveID(UpfN4Layer.UpfIp, 0)
	if err != nil {
		rlogger.Trace(types.ModuleSmf, rlogger.ERROR, nil, "fail to reserve TEID id : %s", err)
	}
	res.IE.Cause.CauseValue = pfcp.Cause_Request_accepted

	//下面遍历请求消息的pdr为PDI.LocalFTEID带有CHFlag标志位1时，提示UPF分配TEID和IP
	n3Teid := uint32(0)
	n9Teid := uint32(0)
	isPSA := false
	ipv6 := false
	if req.IE.CreatePDRs != nil {
		for k, v := range req.IE.CreatePDRs {
			if v.PDI.LocalFTEID != nil && v.PDI.LocalFTEID.CHFlag == 1 {
				teid, err := idmgr.GetInst().BorrowID(UpfN4Layer.UpfIp)
				if err != nil {
					rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, nil, "ULCL UPF assign the core Local N9 TEID failed:%s", err)
				}
				//InterfaceTypeValue为N9orN9fornon_roaming且InterfaceValue为Core表示为ULCL UPF的N9接口分配TEID和IP
				CreatedPDR := pfcp.IECreatedPDR{}
				CreatedPDR.Set(1)
				CreatedPDR.PDRID.Set(v.PDRID.RuleID)
				CreatedPDR.LocalFTEID = &pfcp.IEFTEID{}
				CreatedPDR.LocalFTEID.CHFlag = 0
				CreatedPDR.IeFlags.Set(pfcp.IeTypeFTeid)
				if v.PDI.SourceInterfaceType.InterfaceTypeValue == pfcp.N9orN9fornon_roaming &&
					v.PDI.SourceInterface.InterfaceValue == pfcp.Core {
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ULCL UPF assign the core Local N9=N6 TEID :%v", types3gpp.Teid(teid))
					if net.ParseIP(configure.UpfConf.N6.Ipv4).To4() != nil {
						CreatedPDR.LocalFTEID.V4Flag = 1
						CreatedPDR.LocalFTEID.IPv4Addr = net.ParseIP(configure.UpfConf.N6.Ipv4).To4()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ULCL UPF assign the core Local N9=N6 IPv4 :%v", net.ParseIP(configure.UpfConf.N6.Ipv4).To4())
					}
					if net.ParseIP(configure.UpfConf.N6.Ipv6).To16() != nil {
						CreatedPDR.LocalFTEID.V6Flag = 1
						CreatedPDR.LocalFTEID.IPv6Addr = net.ParseIP(configure.UpfConf.N6.Ipv6).To16()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ULCL UPF assign the core Local N9=N6 IPv6 :%v", net.ParseIP(configure.UpfConf.N6.Ipv6).To16())
					}
					if n9Teid != 0 {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(n9Teid)
					} else {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(teid)
						n9Teid = teid
						res.IE.IeFlags.Set(pfcp.IeTypeCreatedPdr)
						res.IE.CreatedPDRs = append(res.IE.CreatedPDRs, &CreatedPDR)
					}
				}

				//InterfaceTypeValue为N9orN9fornon_roaming且InterfaceValue为Core表示为PAS-UPF的N9分配TEID和IP
				//InterfaceTypeValue为N3_3GPP_Access与InterfaceValue为Access一样为N3分配TEID和IP
				//都是由CreatedPDR携带上去
				if v.PDI.SourceInterfaceType.InterfaceTypeValue == pfcp.N9orN9fornon_roaming &&
					v.PDI.SourceInterface.InterfaceValue == pfcp.Access {
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "PAS UPF assign the access Local N9=N3 TEID %v", types3gpp.Teid(teid))
					//CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(teid)
					if net.ParseIP(configure.UpfConf.N3.Ipv4).To4() != nil {
						CreatedPDR.LocalFTEID.V4Flag = 1
						CreatedPDR.LocalFTEID.IPv4Addr = net.ParseIP(configure.UpfConf.N3.Ipv4).To4()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "PAS UPF assign the access Local N9=N3 IPv4 %+v", net.ParseIP(configure.UpfConf.N3.Ipv4).To4())
					}
					isPSA = true
					if net.ParseIP(configure.UpfConf.N3.Ipv6).To16() != nil {
						CreatedPDR.LocalFTEID.V6Flag = 1
						CreatedPDR.LocalFTEID.IPv6Addr = net.ParseIP(configure.UpfConf.N3.Ipv6).To16()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "PAS UPF assign the access Local N9=N3 IPv6 %+v", net.ParseIP(configure.UpfConf.N3.Ipv6).To16())
					}
					if n3Teid != 0 {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(n3Teid)
					} else {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(teid)
						n3Teid = teid
						res.IE.IeFlags.Set(pfcp.IeTypeCreatedPdr)
						res.IE.CreatedPDRs = append(res.IE.CreatedPDRs, &CreatedPDR)
					}
				} else if v.PDI.SourceInterfaceType.InterfaceTypeValue == pfcp.N3_3GPP_Access {
					rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ULCL UPF assign the access Local TEID %v", types3gpp.Teid(teid))
					if net.ParseIP(configure.UpfConf.N3.Ipv4).To4() != nil {
						CreatedPDR.LocalFTEID.V4Flag = 1
						CreatedPDR.LocalFTEID.IPv4Addr = net.ParseIP(configure.UpfConf.N3.Ipv4).To4()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ULCL UPF assign the access Local Ipv4 %+v ", net.ParseIP(configure.UpfConf.N3.Ipv4).To4())
					}
					if net.ParseIP(configure.UpfConf.N3.Ipv6).To16() != nil {
						CreatedPDR.LocalFTEID.V6Flag = 1
						CreatedPDR.LocalFTEID.IPv6Addr = net.ParseIP(configure.UpfConf.N3.Ipv6).To16()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "ULCL UPF assign the access Local Ipv6 %+v ", net.ParseIP(configure.UpfConf.N3.Ipv6).To16())
					}
					if n3Teid != 0 {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(n3Teid)
					} else {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(teid)
						n3Teid = teid
						res.IE.IeFlags.Set(pfcp.IeTypeCreatedPdr)
						res.IE.CreatedPDRs = append(res.IE.CreatedPDRs, &CreatedPDR)
					}
				} else if v.PDI.SourceInterface.InterfaceValue == pfcp.Access {
					if net.ParseIP(configure.UpfConf.N3.Ipv4).To4() != nil {
						CreatedPDR.LocalFTEID.V4Flag = 1
						CreatedPDR.LocalFTEID.IPv4Addr = net.ParseIP(configure.UpfConf.N3.Ipv4).To4()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "UPF assign the access Local Ipv4 %+v ", net.ParseIP(configure.UpfConf.N3.Ipv4).To4())
					}
					if net.ParseIP(configure.UpfConf.N3.Ipv6).To16() != nil {
						CreatedPDR.LocalFTEID.V6Flag = 1
						CreatedPDR.LocalFTEID.IPv6Addr = net.ParseIP(configure.UpfConf.N3.Ipv6).To16()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "UPF assign the access Local Ipv6 %+v ", net.ParseIP(configure.UpfConf.N3.Ipv6).To16())
					}
					if n3Teid != 0 {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(n3Teid)
						if !isPSA {
							res.IE.IeFlags.Set(pfcp.IeTypeCreatedPdr)
							res.IE.CreatedPDRs = append(res.IE.CreatedPDRs, &CreatedPDR)
						}
					} else {
						CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(teid)
						n3Teid = teid
						res.IE.IeFlags.Set(pfcp.IeTypeCreatedPdr)
						res.IE.CreatedPDRs = append(res.IE.CreatedPDRs, &CreatedPDR)
					}
				} else if v.PDI.SourceInterface.InterfaceValue == pfcp.CP_function && !isPSA {
					if net.ParseIP(UpfN4Layer.UpfIp).To4() != nil {
						CreatedPDR.LocalFTEID.V4Flag = 1
						CreatedPDR.LocalFTEID.IPv4Addr = net.ParseIP(UpfN4Layer.UpfIp).To4()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "UPF CP_function Ipv4 %+v ", net.ParseIP(UpfN4Layer.UpfIp).To4())
					}
					if net.ParseIP(UpfN4Layer.UpfIp).To16() != nil {
						CreatedPDR.LocalFTEID.V6Flag = 1
						CreatedPDR.LocalFTEID.IPv6Addr = net.ParseIP(UpfN4Layer.UpfIp).To16()
						rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "UPF CP_function Ipv6 %+v ", net.ParseIP(UpfN4Layer.UpfIp).To16())
					}

					ipv6 = true
					CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(teid)
					res.IE.IeFlags.Set(pfcp.IeTypeCreatedPdr)
					res.IE.CreatedPDRs = append(res.IE.CreatedPDRs, &CreatedPDR)
				}
				req.IE.CreatePDRs[k].PDI.LocalFTEID = CreatedPDR.LocalFTEID
			}
		}
	}
	upfCxt := StoreUpfN4Context(req)
	if upfCxt == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID), "Store UPF N4 context from req failed,create context space filled with 0:Failure of parameter validity check parameter.")
		res.IE.Cause.CauseValue = pfcp.Cause_System_failure
		upfCxt = &n4context.N4SessionContext{}
	} else {
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(upfCxt.SEID), "Success store session context from session establishment request,UPF context:%+v", upfCxt)
	}
	//建立起seid字符串到seid之间的映射，方便在后续过程中对日志进行筛选
	//logcap.UserIdToSeid.Add(utils2.StrTransId(utils2.Seid(upfCxt.SEID)), upfCxt.SEID) //1
	if isPSA && ipv6 {
		for _, v1 := range req.IE.CreatePDRs {
			if v1.PDI.SourceInterface.InterfaceValue == pfcp.CP_function {
				for k, v2 := range res.IE.CreatedPDRs {
					if v1.PDRID.RuleID == v2.PDRID.RuleID {
						res.IE.CreatedPDRs = append(res.IE.CreatedPDRs[:k], res.IE.CreatedPDRs[k+1:]...)
					}
				}
			}
		}
	}

	// Dnn 错误处理
	if upfCxt.Cause != pfcp.Cause_Reserved {
		res.IE.Cause.CauseValue = upfCxt.Cause
		//	释放N4上下文
		err := ExceptionSessionRelease(upfCxt)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(upfCxt.SEID), "Failure of exception session release.")
		}
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(upfCxt.SEID), "Session released for some unknown  reason,upfCxt.Cause:%+v", upfCxt.Cause)
	}
	if upfCxt.MetricItems != nil {
		metric.Get(metrics.SetupSessiontime, upfCxt.MetricItems).Inc(time.Now().Unix() + 2209017600)
	}
	// 发送原因为“成功”的N4会话建立响应;
	// N4 Session Establishment Response
	// 返回响应消息构造
	res.PfcpHeader.Version = pfcp.Version
	res.PfcpHeader.MPFlag = 0
	res.PfcpHeader.SFlag = 1

	res.PfcpHeader.MessageType = pfcp.PFCP_Session_Establishment_Response
	res.PfcpHeader.SEID = req.IE.CPFSEID.SEID
	res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber

	//res.IE.NodeID todo
	res.IE.NodeID.Set()
	if net.ParseIP(UpfN4Layer.UpfIp).To4() == nil {
		res.IE.NodeID.NodeIDType = pfcp.NodeIDType_IPv6_address
		res.IE.NodeID.SetValue(pfcp.NodeIDType_IPv6_address, []byte(net.ParseIP(UpfN4Layer.UpfIp).To16()))
	} else {
		res.IE.NodeID.NodeIDType = pfcp.NodeIDType_IPv4_address
		res.IE.NodeID.SetValue(pfcp.NodeIDType_IPv4_address, []byte(net.ParseIP(UpfN4Layer.UpfIp).To4()))
	}
	// 可选IE
	//res.IE.UPFSEID
	res.IE.UPFSEID = &pfcp.IEFSEID{}
	res.IE.UPFSEID.Set()
	res.IE.UPFSEID.SEID = upfCxt.SEID
	rlogger.InitUserTrace(upfCxt.IMSI.GetRloggerImsi(), utils2.Seid(upfCxt.SEID))
	rlogger.InitUserTrace(upfCxt.IMSI.GetRloggerImsi(), upfCxt.UeIp)
	if n3Teid != 0 {
		rlogger.InitUserTrace(upfCxt.IMSI.GetRloggerImsi(), utils2.Teid(n3Teid))
	}
	if n9Teid != 0 {
		rlogger.InitUserTrace(upfCxt.IMSI.GetRloggerImsi(), utils2.Teid(n9Teid))
	}
	if net.ParseIP(UpfN4Layer.UpfIp).To4() == nil {
		res.IE.UPFSEID.V6Flag = 1
		res.IE.UPFSEID.IPv6Addr = net.ParseIP(UpfN4Layer.UpfIp).To16()
	} else {
		res.IE.UPFSEID.V4Flag = 1
		res.IE.UPFSEID.IPv4Addr = net.ParseIP(UpfN4Layer.UpfIp).To4()
	}

	res.IE.IeFlags.Set(pfcp.IeTypeFSeid)
	if req.IE.CreatePDRs != nil && req.IE.CreatePDRs[0].PDI.LocalFTEID.CHFlag == 1 {
		/*res.IE.CreatedPDR = &pfcp.IECreatedPDR{}
		res.IE.CreatedPDR.Set(1)
		res.IE.CreatedPDR.PDRID.Set(1)
		idmgr.GetInst().RegisterIDMgr(UpfN4Layer.UpfIp, types.MaxNumSmfTeid)
		err := idmgr.GetInst().ReserveID(UpfN4Layer.UpfIp, 0)
		if err != nil {
			rlogger.Trace(types.ModuleSmf, rlogger.ERROR, nil, "fail to reserve TEID id : %s", err)
		}
		teid, err := idmgr.GetInst().BorrowID(UpfN4Layer.UpfIp)
		rlogger.Trace(moduleTag, rlogger.DEBUG, utils2.Seid(upfCxt.SEID), "PDI.LocalFTEID.CHFlag %+v", teid)
		if err != nil {
			rlogger.Trace(types.ModuleSmfN4, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID), "UPF assign the Local TEID failed:%s", err)
		}

		res.IE.CreatedPDR.LocalFTEID.V4Flag = 1
		//res.IE.CreatedPDR.LocalFTEID.V6Flag=1
		res.IE.CreatedPDR.LocalFTEID.TEID = types3gpp.Teid(teid)
		err = userstrace.AddUser(packet.TEID(res.IE.CreatedPDR.LocalFTEID.TEID), packet.SEID(upfCxt.SEID))
		if err != nil {
			rlogger.Trace(types.ModuleSmfN4, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "set user id UL teid to seid  failed:%s", err)
		}
		res.IE.CreatedPDR.LocalFTEID.IPv4Addr = net.ParseIP(UpfN4Layer.N3Ip).To4() //configure.SmfConf.N3Conf.UPFIP // upf n3 ip
		//res.IE.CreatedPDR.LocalFTEID.IPv6Addr = net.ParseIP(UpfN4Layer.N3Ip).To16() //configure.SmfConf.N3Conf.UPFIP // upf n3 ip
		res.IE.CreatedPDR.IeFlags.Set(pfcp.IeTypeFTeid)
		res.IE.IeFlags.Set(pfcp.IeTypeCreatedPdr)
		if upfCxt.PDRs != nil {
			for k, v := range upfCxt.PDRs {
				if v.PDI.SourceInterface.InterfaceValue == pfcp.Access {
					upfCxt.PDRs[k].PDI.LocalFTEID = &res.IE.CreatedPDR.LocalFTEID
					upfCxt.LocalFTEID[res.IE.CreatedPDR.PDRID.RuleID] = &res.IE.CreatedPDR.LocalFTEID
				}
			}
		}*/
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(upfCxt.SEID), "Fill response PFCP header:\n version : %d\nMPFlag S flag MessageType SEID sequence number,fill IE with %+v", res.PfcpHeader, res.IE)
	// 释放req.PfcpHeader.SEID 的会话
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(req.PfcpHeader.SEID),
	//"Session Establishment Response:(MessageType %v,SEID %v,SequenceNumber %v,UPF SEID %v)",
	//res.PfcpHeader.MessageType, res.PfcpHeader.SEID, res.PfcpHeader.SequenceNumber, res.IE.UPFSEID.SEID)
	//rlogger.Trace(moduleTag, rlogger.INFO, req, "  .MessageType    %v", res.PfcpHeader.MessageType)
	//rlogger.Trace(moduleTag, rlogger.INFO, req, "  .SEID           %v", res.PfcpHeader.SEID)
	//rlogger.Trace(moduleTag, rlogger.INFO, req, "  .SequenceNumber %v", res.PfcpHeader.SequenceNumber)
	//rlogger.Trace(moduleTag, rlogger.INFO, req, "  .UPF SEID %v", res.IE.UPFSEID.SEID)

	// todo: test 应用规则
	/*tuple := &pdr.IpPacketHeaderFields{
		SrcIp:     net.ParseIP("192.0.2.10"),
		SrcPort:   5000,
		DstIp:     net.ParseIP("192.0.2.20"),
		DstPort:   7000,
		Protocol:  6,
		Direction: nasie.DownlinkOnly,
	}
	packetDetectionRule, _ := pdr.LookupPDRs(tuple)
	fmt.Printf("packetDetectionRule :%+v", packetDetectionRule)
	*/
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Sucess handle session establishment request")
	return nil
}

func StoreUpfN4Context(req pfcp.SessionEstablishmentRequest) *n4context.N4SessionContext {
	rlogger.FuncEntry(moduleTag, utils2.Seid(req.PfcpHeader.SEID))
	// 上下文中维护SMF SEID与 UFP SEID的对应关系
	seid, err := n4context.GetSEID()
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID), "Get Session ID failed:%s", err)
		return nil
	}
	// N4 session context
	n4Cxt := &n4context.N4SessionContext{}
	n4Cxt.SEID = seid // key upf 本地SEID
	n4Cxt.SmfSEID = req.IE.CPFSEID
	n4Cxt.PDRs = req.IE.CreatePDRs
	if req.IE.UserID != nil &&
		req.IE.UserID.IMSI != "" {
		n4Cxt.IMSI.StoreImsiString(req.IE.UserID.IMSI, types3gpp.CheckMncLen(req.IE.UserID.IMSI))
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "n4Cxt IMSI %+v", n4Cxt.IMSI)
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "n4Cxt IMSI GetRloggerImsi %+v", n4Cxt.IMSI.GetRloggerImsi())
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Store upf n4 context:upf SEID %v,smf SEID %v,PDRs length:%d",
		n4Cxt.SEID, n4Cxt.SmfSEID, len(n4Cxt.PDRs))
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "  .SEID:       %v", n4Cxt.SEID)
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "  .Smf SEID:   %v", n4Cxt.SEID)
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "  .PDRs length:%d", len(n4Cxt.PDRs))

	// 可选参数
	n4Cxt.URRs = req.IE.CreateURRs
	n4Cxt.QERs = req.IE.CreateQERs
	n4Cxt.FARs = req.IE.CreateFARs
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Store upf n4 context:create FARs length:%d", len(n4Cxt.FARs))
	// paging support
	n4Cxt.BAR = req.IE.CreateBAR
	if n4Cxt.BAR != nil && n4Cxt.BAR.SugBuffPacketsCount.CountValue == 0 {
		// 使用SugBuffPacketsCount作为down link data 的初始值
		n4Cxt.BAR.SugBuffPacketsCount.CountValue = 255
	}

	n4Cxt.CreateTrafficEndpoints = req.IE.CreateTrafficEndpoints
	n4Cxt.PDNType = req.IE.PDNType
	n4Cxt.UserPlaneInactivityTimer = req.IE.UserPlaneInactivityTimer
	n4Cxt.UserID = req.IE.UserID
	n4Cxt.TraceInformation = req.IE.TraceInformation
	// 申请空间
	n4Cxt.LocalFTEID = make(map[uint16]*pfcp.IEFTEID)
	n4Cxt.NetworkInstance = make(map[uint16]*pfcp.IENetworkInstance)
	n4Cxt.PDRQFIs = make(map[uint16][]*pfcp.IEQFI)
	n4Cxt.SDFFilters = make(map[uint16][]*pfcp.IESDFFilter)
	n4Cxt.ApplicationID = make(map[uint16]*pfcp.IEApplicationID)
	n4Cxt.EthPacketFilters = make(map[uint16][]*pfcp.IEEthernetPacketFilter)
	for i, v := range req.IE.CreatePDRs {
		if v.PDI.SourceInterface.InterfaceValue == pfcp.CP_function {
			var n4gtptable n4gtpcontext.N4GtpEntry
			n4gtptable.Teid = uint32(v.PDI.LocalFTEID.TEID)
			n4gtptable.Seid = n4Cxt.SEID
			err = n4gtpcontext.Update(uint32(v.PDI.LocalFTEID.TEID), &n4gtptable)
			if err != nil {
				rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Add upf context failed:%s", err)
				// 错误继续执行，后面MetricItems需要初始化
				//return nil
			}
		}

		//	CN tunnel info.
		n4Cxt.LocalFTEID[v.PDRID.RuleID] = v.PDI.LocalFTEID // PDR对应的TEID
		//-	Network instance.
		n4Cxt.NetworkInstance[v.PDRID.RuleID] = v.PDI.NetworkInstance
		//-	QFIs.
		n4Cxt.PDRQFIs[v.PDRID.RuleID] = v.PDI.QFIs
		//-	IP Packet Filter Set
		// todo: 设置为json格式,放通
		/*if v.PDRID.RuleID == 1 && len(v.PDI.SDFFilters) > 0 {
			v.PDI.SDFFilters[0].FlowDescription = []byte(`{"action":"permit","dir":"in","proto":"ip","src_ip":"192.168.240.0/0","dst_ip":"192.168.103.200/0","src_port":"0","dst_port":"0"}`)
		} else if len(v.PDI.SDFFilters) > 0 {
			v.PDI.SDFFilters[0].FlowDescription = []byte(`{"action":"permit","dir":"out","proto":"ip","src_ip":"172.16.3.200/0","dst_ip":"192.168.240.0/0","src_port":"0","dst_port":"0-0"}`)

		}*/
		n4Cxt.SDFFilters[v.PDRID.RuleID] = v.PDI.SDFFilters
		//Application Identifier
		n4Cxt.ApplicationID[v.PDRID.RuleID] = v.PDI.ApplicationID
		//Ethernet Packet Filter Set
		n4Cxt.EthPacketFilters[v.PDRID.RuleID] = v.PDI.EthPacketFilters
		if v.PDI.LocalFTEID != nil {
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Store upf n4 context:PDRs[%d].LocalFTEID.TEID:%v", i, v.PDI.LocalFTEID.TEID)
		}
		if v.PDI.QFIs != nil {
			if v.PDI.QFIs[0] != nil {
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Store upf n4 context:PDRs[%d].PDI.QFIs[0]:%v", i, v.PDI.QFIs[0].Value)
			}
		}

	}
	// 23.501 5.8.3.2	Buffering at UPF
	n4Cxt.Buffer = list.New()

	// todo counter
	n4Cxt.MetricItems, err = metrics.SessionCounterInit()
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Add upf context Counter failed:%s", err)
		err := metrics.SessionMeterRelease(n4Cxt.MetricItems)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Release upf context Counter failed:%s", err)
			//return nil
		}
		return nil
	}
	n4Cxt.MetricItemsSnapshot, err = metrics.SessionCounterInit()
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Add upf context counter snapshot failed:%s", err)
		err := metrics.SessionMeterRelease(n4Cxt.MetricItems)
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Release upf context counter failed:%s", err)
			//return nil
		}
		return nil
	}
	// 保存当前上下文
	err = n4context.AddIndexN4Context(n4context.N4SessionIDKey(seid), n4Cxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Add upf context failed:%s", err)
		return nil
	}
	// 存储并应用请求中收到的规则
	err = pdr.ConfigPDRsTable(n4Cxt) //todo:更新1.1 ConfigPDRsTable(n4Cxt) //Configuration rule table
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Config PDRs table failed:%s", err)
	}
	return n4Cxt
}

// UpfPasUpfTable 储存PAS-UPF(包括主锚点和辅助锚点)(key为DNN,value为PAS-UPF)
// UpfIUpf 保存I-UPF(上行分类器)
// var UpfPasUpfTable =make(map[string]*pfcp.IEFTEID)
var UpfIUpf *pfcp.IEFTEID

//func ClearRedisAllN4Session() {
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	var cursor uint64
//	for {
//		var keys []string
//		keys, cursor, err := redisclt_v2.Agent.HScan(ctx, "UPF_POOL_N4Session", cursor, key+"*", 20).Result()
//		if err != nil {
//			break
//		}
//		for i := 0; i < len(keys); i = i + 2 {
//			redisclt_v2.Agent.HDel(ctx,"UPF_POOL_N4Session",keys[i])
//		}
//		if cursor == 0 {
//			break
//		}
//	}
//}
//func InitSeidUpfN4CxtTable(){
//	rlogger.FuncEntry(moduleTag, nil)
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	cmd :=redisclt_v2.Agent.Exists(ctx,"UPF_POOL_N4Session")
//	cmd1 :=redisclt_v2.Agent.Exists(ctx,"UPF_POOL_N4Node")
//	l:=n4context.LengthOfN4ContextTbl(n4context.N4SessionIDCxtType)
//	//cmd.Val()!=1:表明redis里面没有N4SessionContext
//	if cmd.Val() != 1 || l!=0{
//		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "redis not have UPF N4Session")
//		return
//	}
//	//cmd.Val() == 1 && cmd1.Val() !=1:表明redis里面没有N4SessionContext却有N4Node
//	if cmd.Val() == 1 && cmd1.Val() !=1{
//		rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "redis not have UPF N4 Node but have N4Session,doing clean n4session in redis")
//		ClearRedisAllN4Session()
//		return
//	}
//	var cursor uint64
//	for {
//		var keys []string
//		keys, cursor, err := redisclt_v2.Agent.HScan(ctx, "UPF_POOL_N4Session", cursor, configure.UpfConf.N4.Local.Ipv4+"_*", 20).Result()
//		if err != nil {
//			break
//		}
//		for i := 0; i < len(keys); i = i + 2 {
//			byte,err:= redisclt_v2.Agent.HGet(ctx,"UPF_POOL_N4Session" ,keys[i]).Bytes()
//			if err != nil {
//				continue
//			}
//			ctxt:=&n4context.N4SessionContext{}
//			jsoniter.Unmarshal(byte,ctxt)
//			//json.Unmarshal(byte,ctxt)
//			s:=strings.Split(keys[i],"_")
//			seid,_:=strconv.Atoi(s[2])
//			//redisclt_v2.Agent.Exists(ctx,"UPF_POOL_N4Session",)
//			//ctxt.MetricItems=metric.NewMetricsMap()
//			//ctxt.MetricItemsSnapshot=metric.NewMetricsMap()
//			ctxt.MetricItems,_= metrics.SessionCounterInit()
//			ctxt.MetricItemsSnapshot,_= metrics.SessionCounterInit()
//			//n4context.AddIndexN4Context(n4context.N4SessionIDKey(seid),ctxt)
//			n4context.AddN4ContextFromRedis(n4context.N4SessionIDKey(seid),ctxt)
//			err = pdr.ConfigPDRsTable(ctxt)
//			if err != nil {
//				rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(ctxt.SEID), "Config PDRs table failed:%s", err)
//			}
//		}
//		if cursor == 0 {
//			break
//		}
//	}
//	rlogger.Trace(moduleTag, rlogger.DEBUG, nil, "UPF successfully pull N4Session from redis")
//}

// N4 Session Modify Request b
func (s *N4Msg) SessionModifyRequest(req pfcp.SessionModifyRequest,
	res *pfcp.SessionModifyResponse) (ret error) {
	//	rlogger.FuncEntry(moduleTag, rlogger.Seid(req.PfcpHeader.SEID))
	rlogger.FuncEntry(moduleTag, utils2.Seid(req.PfcpHeader.SEID))
	//N4 Session Establishment Response
	if req.PfcpHeader.MessageType != pfcp.PFCP_Session_Modification_Request {
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Message type error:message type should be session modification request,rather than type:%+v", req.PfcpHeader.MessageType)
		return errors.New("Session modify request message type error: " +
			strconv.Itoa(int(req.PfcpHeader.MessageType)))
	}
	//fmt.Printf("SessionModifyRequest: %+v\n", req)
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID),
		"Received  session modification request message,request header: %+v", req.PfcpHeader)
	// 读取当前上下文
	n4Cxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(req.PfcpHeader.SEID))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(req.PfcpHeader.SEID), "Failed to get N4 context and exit to handle this message, "+
			"error:%s", err)
		return err
	}

	//n4Cxt = n4Cxt.Copy()
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Get N4 context success,start updating N4 context %+v", n4Cxt.SEID)
	// 填充UPF N4上下文,pfcpHeader中携带的是local SEID
	n4Cxt.SEID = req.PfcpHeader.SEID
	// 可选参数

	// 更新上下文
	// PDRs
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start creating PDRs in session:%v,need to "+
		"creating %d PDRs,now exist %d PDRs", n4Cxt.SEID, len(req.IE.CreatePDRs), len(n4Cxt.PDRs))
	for _, src := range req.IE.CreatePDRs {
		if src == nil {
			//rlogger.Trace(moduleTag,rlogger.INFO,nil,"Failed to update PDR because the PDR from request PDRs is nil")
			continue
		}
		have := false
		// 更新上下文中的PDRs
		for _, dst := range n4Cxt.PDRs {
			if dst == nil {
				continue
			}
			if dst.PDRID.RuleID == src.PDRID.RuleID {
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "PDR %+v already exists,no need to create", src.PDRID)
			}
		}
		// pdr id 不存在,创建pdr
		if !have {
			n4Cxt.PDRs = append(n4Cxt.PDRs, src)
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "PDR is not exists ,create PDR %+v success in session"+
				" %+v", src.PDRID, n4Cxt.SEID)
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished create of PDRs in session %+v,now exist %d PDRs", n4Cxt.SEID, len(n4Cxt.PDRs))
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start update PDRs in session:%v,need to "+
		"update %d PDRs,now exist %d PDRs", n4Cxt.SEID, len(req.IE.UpdatePDRs), len(n4Cxt.PDRs))
	for _, src := range req.IE.UpdatePDRs {
		if src == nil {
			//rlogger.Trace(moduleTag,rlogger.INFO,nil,"Failed to update PDR because the PDR from request PDRs is nil")
			continue
		}
		have := false
		// 更新上下文中的PDRs
		for i, dst := range n4Cxt.PDRs {
			if dst == nil {
				continue
			}
			if dst.PDRID.RuleID == src.PDRID.RuleID {
				if src.OuterHeaderRemoval != nil {
					n4Cxt.PDRs[i].OuterHeaderRemoval = src.OuterHeaderRemoval
				}
				if src.Precedence != nil {
					n4Cxt.PDRs[i].Precedence = *src.Precedence
				}
				if src.PDI != nil {
					n4Cxt.PDRs[i].PDI = *src.PDI
				}
				if src.FARID != nil {
					n4Cxt.PDRs[i].FARID = src.FARID
				}
				if src.URRID != nil {
					n4Cxt.PDRs[i].URRIDs = src.URRID
				}
				if src.QERID != nil {
					n4Cxt.PDRs[i].QERIDs = src.QERID
				}
				if src.ActivatePredefinedRules != nil {
					for _, srcAct := range src.ActivatePredefinedRules {
						n4Cxt.PDRs[i].ActPredefinedRules = append(n4Cxt.PDRs[i].ActPredefinedRules, srcAct)
					}
				}
				if src.DeactivatePredefinedRules != nil {
					for n, srcDAct := range src.DeactivatePredefinedRules {
						if n4Cxt.PDRs[i].ActPredefinedRules[n].RulesName == srcDAct.RulesName {
							n4Cxt.PDRs[i].ActPredefinedRules = append(n4Cxt.PDRs[i].ActPredefinedRules[:n], n4Cxt.PDRs[i].ActPredefinedRules[n+1:]...)
						}
					}
				}
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "PDR %+v already update,", src.PDRID)
			}
		}
		// pdr id 不存在
		if !have {
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "PDR is not exists ,no need to update")
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished update of PDRs in session %+v,now exist %d PDRs", n4Cxt.SEID, len(n4Cxt.PDRs))
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start remove PDRs in session:%v,need to "+
		"remove %d PDRs,now exist %d PDRs", n4Cxt.SEID, len(req.IE.RemovePDRs), len(n4Cxt.PDRs))
	for _, src := range req.IE.RemovePDRs {
		if src == nil {
			//rlogger.Trace(moduleTag,rlogger.INFO,nil,"Failed to update PDR because the PDR from request PDRs is nil")
			continue
		}
		have := false
		// 更新上下文中的PDRs
		for i, dst := range n4Cxt.PDRs {
			if dst == nil {
				continue
			}
			if dst.PDRID.RuleID == src.PDRID.RuleID {
				n4Cxt.PDRs = append(n4Cxt.PDRs[:i], n4Cxt.PDRs[i+1:]...)
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "PDR %+v already remove", src.PDRID)
			}
		}
		// pdr id 不存在
		if !have {
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "PDR is not exists ,no need to remove")
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished remove of PDRs in session %+v,now exist %d PDRs", n4Cxt.SEID, len(n4Cxt.PDRs))
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start creating FARs in session:%v,need to creating %d FARs,"+
		"now exist %d FARs", n4Cxt.SEID, len(req.IE.CreateFARs), len(n4Cxt.FARs))
	for _, src := range req.IE.CreateFARs {
		if src == nil {
			//rlogger.Trace(moduleTag,rlogger.INFO,nil,"Failed to update PDR because the PDR from request PDRs is nil")
			continue
		}
		have := false
		// 更新上下文中的FARs
		for _, dst := range n4Cxt.FARs {
			if dst == nil {
				continue
			}
			if dst.FARID.Value == src.FARID.Value {
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "FAR %+v already exists,no need to create", src.FARID)
			}
		}
		// pdr id 不存在,创建pdr
		if !have {
			n4Cxt.FARs = append(n4Cxt.FARs, src)
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "FAR is not exists ,create FAR %+v success in session"+
				" %+v", src.FARID, n4Cxt.SEID)
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished create of FARs in session %+v,now exist %d FARs", n4Cxt.SEID, len(n4Cxt.FARs))
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start updating FARs in session:%v,need to update %d FARs,"+
		"now exist %d FARs", n4Cxt.SEID, len(req.IE.UpdateFARs), len(n4Cxt.FARs))
	// FARs
	for _, src := range req.IE.UpdateFARs {
		if src == nil {
			continue
		}
		have := false
		//当上行PDR的InterfaceTypeValue为N3_3GPP_Access表明此为I-UPF
		//UpfPasUpfTable储存PAS-UPF(辅助锚点)(key为DNN,value为PAS-UPF)
		//if n4Cxt.PDRs[0].PDI.SourceInterfaceType.InterfaceTypeValue==pfcp.N3_3GPP_Access&&
		//	n4Cxt.PDRs[0].PDI.SourceInterface.InterfaceValue==pfcp.Access&&
		//	src.UpdateForwardingPara.OuterHeaderCreation!=nil&&
		//	src.UpdateForwardingPara.DstInterface.Value==pfcp.Core{
		//	//UpfPasUpfLocalTeidMap
		//	localTeid:=pfcp.IEFTEID{}
		//	localTeid.IPv4Addr=src.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr.To16()
		//	localTeid.IPv6Addr=src.UpdateForwardingPara.OuterHeaderCreation.IPv6Addr.To16()
		//	localTeid.TEID=src.UpdateForwardingPara.OuterHeaderCreation.TEID
		//	tmpBytes := []byte(src.UpdateForwardingPara.NetworkInstance.NetworkInstance)
		//	tmplen := byte(len(tmpBytes))
		//	tmpBytes = append([]byte{tmplen}, tmpBytes...)
		//	apn := types3gpp.Apn{}
		//	apnBuff := bytes.NewReader(tmpBytes)
		//	apn.Decode(apnBuff)
		//	//dnn:= strings.Trim(src.UpdateForwardingPara.NetworkInstance.NetworkInstance, "\u0003")
		//	dnn :=apn.String()
		//	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID),
		//		"dnn apn String: %s", dnn)
		//	//UpfPasUpfTable[dnn]=&localTeid
		//	StorePasUpf(dnn,&localTeid)
		//}
		////当上行PDR的InterfaceTypeValue为N9orN9fornon_roaming表明此为PAS-UPF
		////UpfIUpf保存下发的上行分类器的IP和TEID
		//if  n4Cxt.PDRs[0].PDI.SourceInterfaceType.InterfaceTypeValue==pfcp.N9orN9fornon_roaming&&
		//	n4Cxt.PDRs[0].PDI.SourceInterface.InterfaceValue==pfcp.Access&&
		//	src.UpdateForwardingPara.OuterHeaderCreation!=nil{
		//	//UpfIUpf
		//	localTeid:=pfcp.IEFTEID{}
		//	localTeid.TEID=src.UpdateForwardingPara.OuterHeaderCreation.TEID
		//	localTeid.IPv4Addr=src.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr.To16()
		//	localTeid.IPv6Addr=src.UpdateForwardingPara.OuterHeaderCreation.IPv6Addr.To16()
		//	UpfIUpf=&localTeid
		//}

		// 更新上下文中的FARs
		//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "Src Update FAR Len:%d", len(req.IE.UpdateFARs))
		//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "Dst Cxt FAR len:%d", len(n4Cxt.FARs))
		for i, dst := range n4Cxt.FARs {
			if dst == nil {
				continue
			}

			if dst.FARID.Value == src.FARID.Value {
				if n4Cxt.FARs[i].ForwardingParameters != nil &&
					n4Cxt.FARs[i].ForwardingParameters.DstInterface.Value == pfcp.Access &&
					src.UpdateForwardingPara != nil && src.UpdateForwardingPara.DstInterface != nil &&
					src.UpdateForwardingPara.DstInterface.Value == pfcp.Core &&
					src.UpdateForwardingPara.OuterHeaderCreation != nil {
					// 此场景为N2切换，不修改gnb信息，仅将新gnb信息存储下来
					rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "N2 handover modify start,new gnbip :%+v",
						src.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr)
					n4Cxt.NewGnbInfo.Ip.IP = src.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr
					n4Cxt.NewGnbTeid = src.UpdateForwardingPara.OuterHeaderCreation.TEID
					have = true
					break
				} else if src.UpdateForwardingPara != nil && src.UpdateForwardingPara.DstInterface != nil &&
					src.UpdateForwardingPara.DstInterface.Value == pfcp.Access &&
					src.UpdateForwardingPara.OuterHeaderCreation != nil {
					// 此场景为ipv6 RS/RA流程中，SMF发往UPF N4GTP口的RA消息通过UPF转发往gnb所需的gnbInfo
					rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "*** ipv6 ****\nupf get gnb info : [gnb_ip : %+v gnb_teid : %+v]",
						src.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr, src.UpdateForwardingPara.OuterHeaderCreation.TEID)
					n4Cxt.GnbIp = src.UpdateForwardingPara.OuterHeaderCreation.IPv4Addr
					n4Cxt.GnbTeid = src.UpdateForwardingPara.OuterHeaderCreation.TEID
				}
				have = true
				//dst.FARID = src.FARID
				//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "Src FAR:%+v", src)
				//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "Dst FAR:%+v", dst)
				dst.ApplyAction = src.ApplyAction
				UpdateForwardParameters(src, dst)
				dst.BARID = src.BARID

				//标识当前为idle态，active为更新为12
				if dst.ForwardingParameters != nil &&
					dst.ForwardingParameters.DstInterface.Value == pfcp.IEDestinationInterface_Access &&
					dst.ApplyAction.Flag == uint8(pdr.NOCPBUFF) {
					if n4Cxt.BufferState == true {
						n4Cxt.Buffer = list.New()
					}
					n4Cxt.BufferState = true
				} else if dst.ForwardingParameters != nil &&
					dst.ForwardingParameters.DstInterface.Value == pfcp.IEDestinationInterface_Access {
					n4Cxt.BufferState = false
				}
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID),
					"Dst applyAction flag(%v),buffer state(%v)", dst.ApplyAction.Flag, n4Cxt.BufferState)
				//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "Src FAR:%+v", src)
				//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "Dst FAR:%+v", dst)

			}
		}
		// far id 不存在,返回 73
		if !have {
			res.PfcpHeader.Version = pfcp.Version
			res.PfcpHeader.MPFlag = 0
			res.PfcpHeader.SFlag = 1

			res.PfcpHeader.MessageType = pfcp.PFCP_Session_Modification_Response
			res.PfcpHeader.SEID = n4Cxt.SmfSEID.SEID
			res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
			//res.IE.Cause.Set()
			res.IE.Cause.CauseValue = pfcp.Cause_Rule_creation_modification_Failure
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "The PDR need to be "+
				"modified in session %+v is "+"not exists,then fill cause value:%+v to send response "+
				"message,and end N4 context "+
				"modification process", n4Cxt.SEID, res.IE.Cause.CauseValue)
			return nil
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "FARs update finished in session:%+v", n4Cxt.SEID)
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start remove FARs in session:%v,need to remove %d FARs,"+
		"now exist %d FARs", n4Cxt.SEID, len(req.IE.RemoveFARs), len(n4Cxt.FARs))
	for _, src := range req.IE.RemoveFARs {
		if src == nil {
			//rlogger.Trace(moduleTag,rlogger.INFO,nil,"Failed to update PDR because the PDR from request PDRs is nil")
			continue
		}
		have := false
		// 更新上下文中的FARs
		for i, dst := range n4Cxt.FARs {
			if dst == nil {
				continue
			}
			if dst.FARID.Value == src.FARID.Value {
				n4Cxt.FARs = append(n4Cxt.FARs[:i], n4Cxt.FARs[i+1:]...)
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "FAR %+v already remove", src.FARID)
			}
		}
		// pdr id 不存在,创建pdr
		if !have {
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "FAR is not exists")
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished remove of FARs in session %+v,now exist %d FARs", n4Cxt.SEID, len(n4Cxt.FARs))
	} // end FARs

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start creating QERs in session:%v,need to creating %d QERs,"+
		"now exist %d QERs", n4Cxt.SEID, len(req.IE.CreateQERs), len(n4Cxt.QERs))
	for _, src := range req.IE.CreateQERs {
		if src == nil {
			//rlogger.Trace(moduleTag,rlogger.INFO,nil,"Failed to update PDR because the PDR from request PDRs is nil")
			continue
		}
		have := false
		// 更新上下文中的FARs
		for _, dst := range n4Cxt.QERs {
			if dst == nil {
				continue
			}
			if dst.QERID.Value == src.QERID.Value {
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "QER %+v already exists,no need to create", src.QERID)
			}
		}
		// pdr id 不存在,创建pdr
		if !have {
			n4Cxt.QERs = append(n4Cxt.QERs, src)
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "QER is not exists ,create QER %+v success in session"+
				" %+v", src.QERID, n4Cxt.SEID)
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished create of QERs in session %+v,now exist %d QERs", n4Cxt.SEID, len(n4Cxt.QERs))
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start updating QERs in session:%v,need to "+
		"update %d QERs,now exist %d QERs", n4Cxt.SEID, len(req.IE.UpdateQERs), len(n4Cxt.QERs))
	// QER
	for _, src := range req.IE.UpdateQERs {
		if src == nil {
			continue
		}
		have := false
		// 更新上下文中的QERs
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src update QER Len:%d", len(req.IE.UpdateQERs))
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst cxt QER len:%d", len(n4Cxt.QERs))
		for _, dst := range n4Cxt.QERs {
			if dst == nil {
				continue
			}
			if dst.QERID.Value == src.QERID.Value {
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Moved req update QER %+v to N4 QER :%+v ", src, dst)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst QER:%+v", dst)

				UpdateQerParameters(src, dst)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src FAR:%+v", src)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst FAR:%+v", dst)

			}
		}
		// far id 不存在,返回 73
		if !have {
			res.PfcpHeader.Version = pfcp.Version
			res.PfcpHeader.MPFlag = 0
			res.PfcpHeader.SFlag = 1

			res.PfcpHeader.MessageType = pfcp.PFCP_Session_Modification_Response
			res.PfcpHeader.SEID = n4Cxt.SmfSEID.SEID
			res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
			//res.IE.Cause.Set()
			res.IE.Cause.CauseValue = pfcp.Cause_Rule_creation_modification_Failure
			//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Session modify response SMF SEID : %d,cause : %v", n4Cxt.SEID.SEID,
			//	res.IE.Cause.CauseValue)
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "The QER need to be updated in "+
				"session %+v  not exists,then fill cause value:%+v to send response message,and end N4 "+
				"context modification process", n4Cxt.SEID, res.IE.Cause.CauseValue)
			return nil
		}
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "QERs update finished in session:%+v", n4Cxt.SEID)
	} // end QERs
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start remove QERs in session:%v,need to "+
		"remove %d QERs,now exist %d QERs", n4Cxt.SEID, len(req.IE.RemoveQERs), len(n4Cxt.QERs))
	// remove QERs
	for _, src := range req.IE.RemoveQERs {
		if src == nil {
			continue
		}
		have := false
		// 删除上下文中的QERs
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src remove QER Len:%d", len(req.IE.RemoveQERs))
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst cxt QER len:%d", len(n4Cxt.QERs))
		for i, dst := range n4Cxt.QERs {
			if dst == nil {
				continue
			}
			if dst.QERID.Value == src.QERID.Value {
				have = true
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src QER:%+v", src)
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Removed the QER %+v", dst)
				n4Cxt.QERs = append(n4Cxt.QERs[:i], n4Cxt.QERs[i+1:]...)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src FAR:%+v", src)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst FAR:%+v", dst)

			}
		}
		// qer id 不存在,返回 73
		if !have {
			res.PfcpHeader.Version = pfcp.Version
			res.PfcpHeader.MPFlag = 0
			res.PfcpHeader.SFlag = 1

			res.PfcpHeader.MessageType = pfcp.PFCP_Session_Modification_Response
			res.PfcpHeader.SEID = n4Cxt.SmfSEID.SEID
			res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
			//res.IE.Cause.Set()
			res.IE.Cause.CauseValue = pfcp.Cause_Rule_creation_modification_Failure
			//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Session modify response SMF SEID : %d,cause : %v", n4Cxt.SEID.SEID,
			//	res.IE.Cause.CauseValue)
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "The QER %+v need to be removed in "+
				"session %+v is not exists,\nthen fill cause value:%+v to send response message,\nand end N4 "+
				"context modification process", src, n4Cxt.SEID, res.IE.Cause.CauseValue)
			return nil
		}
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "QERs remove finished in session:%+v", n4Cxt.SEID)
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start creating URRs in session:%v,need to creating %d URRs,"+
		"now exist %d URRs", n4Cxt.SEID, len(req.IE.CreateURRs), len(n4Cxt.URRs))
	for _, src := range req.IE.CreateURRs {
		if src == nil {
			//rlogger.Trace(moduleTag,rlogger.INFO,nil,"Failed to update PDR because the PDR from request PDRs is nil")
			continue
		}
		have := false
		// 更新上下文中的FARs
		for _, dst := range n4Cxt.URRs {
			if dst == nil {
				continue
			}
			if dst.URRID.URRIDValue == src.URRID.URRIDValue {
				have = true
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "URR %+v already exists,no need to create", src.URRID)
			}
		}
		// pdr id 不存在,创建pdr
		if !have {
			n4Cxt.URRs = append(n4Cxt.URRs, src)
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "URR is not exists ,create URR %+v success in session"+
				" %+v", src.URRID, n4Cxt.SEID)
		}
		//-	Network instance.
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished create of URRs in session %+v,now exist %d URRs", n4Cxt.SEID, len(n4Cxt.URRs))
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start updating URRs in session:%v,need to "+
		"update %d URRs,now exist %d URRs", n4Cxt.SEID, len(req.IE.UpdateURRs), len(n4Cxt.URRs))
	// Update URRs
	for _, src := range req.IE.UpdateURRs {
		if src == nil {
			continue
		}
		have := false
		// 更新上下文中的URRs
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src update N4 session report len:%d", len(req.IE.UpdateURRs))
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst cxt N4 session report len:%d", len(n4Cxt.URRs))
		for _, dst := range n4Cxt.URRs {
			if dst == nil {
				continue
			}
			if dst.URRID.URRIDValue == src.URRID.URRIDValue {
				have = true
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src N4 session report:%+v", src)
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Move URR %+v to N4  URR %+v ", src, dst)

				UpdateUrrParameters(src, dst)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src FAR:%+v", src)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst FAR:%+v", dst)

			}
		}
		// urr id 不存在,返回 73
		if !have {
			res.PfcpHeader.Version = pfcp.Version
			res.PfcpHeader.MPFlag = 0
			res.PfcpHeader.SFlag = 1

			res.PfcpHeader.MessageType = pfcp.PFCP_Session_Modification_Response
			res.PfcpHeader.SEID = n4Cxt.SmfSEID.SEID
			res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
			//res.IE.Cause.Set()
			res.IE.Cause.CauseValue = pfcp.Cause_Rule_creation_modification_Failure
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "The URR %+v need to be updated in "+
				"session %+v is not exists,\nthen fill cause value:%+v to send response message,\nand end N4 "+
				"context modification process", src, n4Cxt.SEID, res.IE.Cause.CauseValue)
			return nil
		}
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "URRs update finished in session:%+v", n4Cxt.SEID)
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start removing URRs in session:%v,need to "+
		"remove %d URRs,now exist %d URRs", n4Cxt.SEID, len(req.IE.UpdateURRs), len(n4Cxt.URRs))
	//remove URRs
	for _, src := range req.IE.RemoveURRs {
		if src == nil {
			continue
		}
		have := false
		// 删除上下文中的URRs
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src remove N4 session report len:%d", len(req.IE.RemoveURRs))
		//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst cxt N4 session report len:%d", len(n4Cxt.URRs))
		for i, dst := range n4Cxt.URRs {
			if dst == nil {
				continue
			}
			if dst.URRID.URRIDValue == src.URRID.URRIDValue {
				have = true
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src N4 session report:%+v", src)
				rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Removed the URR %+v", dst)
				n4Cxt.URRs = append(n4Cxt.URRs[:i], n4Cxt.URRs[i+1:]...)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Src FAR:%+v", src)
				//rlogger.Trace(moduleTag, rlogger.INFO, n4Cxt, "Dst FAR:%+v", dst)

			}
		}
		// urr id 不存在,返回 73
		if !have {
			res.PfcpHeader.Version = pfcp.Version
			res.PfcpHeader.MPFlag = 0
			res.PfcpHeader.SFlag = 1

			res.PfcpHeader.MessageType = pfcp.PFCP_Session_Modification_Response
			res.PfcpHeader.SEID = n4Cxt.SmfSEID.SEID
			res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
			//res.IE.Cause.Set()
			res.IE.Cause.CauseValue = pfcp.Cause_Rule_creation_modification_Failure
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "The URR %+v need to be removed in "+
				"session %+v is not exists,\nthen fill cause value:%+v to send response message,\nand end N4 "+
				"context modification process", src, n4Cxt.SEID, res.IE.Cause.CauseValue)
			return nil
		}
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "URRs remove finished in session:%+v", n4Cxt.SEID)
	} // end URRs

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start creating BAR in session:%v", n4Cxt.SEID)
	if req.IE.CreateBAR != nil {
		if n4Cxt.BAR != nil {
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "BAR is exists")
		} else {
			n4Cxt.BAR = &pfcp.IECreateBAR{}
			n4Cxt.BAR.Set()
			n4Cxt.BAR.BARID = req.IE.UpdateBAR4SMR.BARID
			n4Cxt.BAR.DLDataNotificationDelay = req.IE.UpdateBAR4SMR.DLDataNotificationDelay
			// 使用SugBuffPacketsCount作为down link data 的初始值
			n4Cxt.BAR.SugBuffPacketsCount = req.IE.UpdateBAR4SMR.SuggestedBufferingPacketsCount
		}
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished create of BAR in session %+v", n4Cxt.SEID)

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start set BAR")
	// BAR
	if req.IE.UpdateBAR4SMR != nil {
		if n4Cxt.BAR == nil {
			n4Cxt.BAR = &pfcp.IECreateBAR{}
			n4Cxt.BAR.Set()
		}
		n4Cxt.BAR.BARID = req.IE.UpdateBAR4SMR.BARID
		n4Cxt.BAR.DLDataNotificationDelay = req.IE.UpdateBAR4SMR.DLDataNotificationDelay
		// 使用SugBuffPacketsCount作为down link data 的初始值
		n4Cxt.BAR.SugBuffPacketsCount = req.IE.UpdateBAR4SMR.SuggestedBufferingPacketsCount
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "BAR set success in session %+v", n4Cxt.SEID)
	} else {
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "No BAR need to update:BAR in request is nil")
	}

	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Start remove BAR in session:%v", n4Cxt.SEID)
	if req.IE.RemoveBAR != nil {
		if n4Cxt.BAR != nil && n4Cxt.BAR.BARID == req.IE.RemoveBAR.BARID {
			n4Cxt.BAR = nil
		} else {
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "BAR is not exists")
		}
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "Finished remove of BAR in session %+v", n4Cxt.SEID)

	// 更新N4上下文
	//rlogger.Trace(moduleTag, rlogger.INFO, rlogger.Seid(n4Cxt.SEID), "upf context update SEID : %d", n4Cxt.SEID)
	err = n4context.UpdateN4Context(n4context.N4SessionIDKey(n4Cxt.SEID), n4Cxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Update config PDRs table failed:%s", err)
	} else {
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Success to update N4 context "+
			"in N4 context table with session key:%+v", n4Cxt.SEID)
	}
	// 存储并应用请求中收到的规则
	err = pdr.ConfigPDRsTableUpdate(n4Cxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Update config PDRs table failed:%s", err)
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Success to update configure PDRs table")
	//test todo
	/*buf := []byte{1, 1, 1, 1, 1, 1, 1, 1}
	n4Cxt.Buffer.PushBack(buf)
	buf1:= []byte{2, 1, 1, 1, 1, 1, 1, 1}
	n4Cxt.Buffer.PushBack(buf1)
	buf2:= []byte{3, 1, 1, 1, 1, 1, 1, 1}
	n4Cxt.Buffer.PushBack(buf2)
	*/
	// todo 激活n3通道时，发送缓存数据到n3
	// 1、发送buffer引用到sendingList
	// 2、守候的处理函数：接收任务，从sendingList中循环获取一个buffer引用，阻塞的发送到buffer chan
	// 3、守候处理函数：从阻塞的buffer chan取消息，并完成发送流程
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Paging send session modify request n4Cxt.Buffer.Len : %d,buffer state : %v", n4Cxt.Buffer.Len(), n4Cxt.BufferState)
	if n4Cxt.Buffer.Len() > 0 && !n4Cxt.BufferState {
		SendingList.Rw.Lock()
		SendingList.SendList.PushBack(n4Cxt.Buffer)
		SendingList.Rw.Unlock()

		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Paging send session modify request sending List.SendList len : %d", SendingList.SendList.Len())
		// 清空buffer
		n4Cxt.Buffer = list.New()
		// 通知有新任务,非阻塞通知
		select {
		case SendingList.State <- struct{}{}:
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Paging send session modify request sending list receive task ")

		default:
			rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Paging send session modify request sending list receive repeat task ")
			//队列已满，丢弃重复的通知
		}
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Paging send sending list length: %d", SendingList.SendList.Len())
		//SendBufferMsg(n4Cxt)
	}

	res.PfcpHeader.Version = pfcp.Version
	res.PfcpHeader.MPFlag = 0
	res.PfcpHeader.SFlag = 1

	res.PfcpHeader.MessageType = pfcp.PFCP_Session_Modification_Response
	res.PfcpHeader.SEID = n4Cxt.SmfSEID.SEID
	res.PfcpHeader.SequenceNumber = req.PfcpHeader.SequenceNumber
	//fmt.Println("smf context update SEID : ", n4Cxt.SEID.SEID)
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Session modify response SMF SEID : %d", n4Cxt.SmfSEID.SEID)
	//res.IE.Cause.Set()
	res.IE.Cause.Set() //Cause_Request_accepted = 1 // (success)
	// todo: test 应用规则
	/*tuple := &pdr.IpPacketHeaderFields{
		SrcIp:     net.ParseIP("192.0.2.10"),
		SrcPort:   5000,
		DstIp:     net.ParseIP("192.0.2.20"),
		DstPort:   7000,
		Protocol:  17,
		Direction: nasie.UplinkOnly,
	}
	packetDetectionRule, _ := pdr.LookupULPDRs(uint32(n4Cxt.PDRs[0].PDI.LocalFTEID.TEID),tuple)
	fmt.Printf("packetDetectionRule :%+v", packetDetectionRule)
	*/
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(req.PfcpHeader.SEID), "N4 context modification completed-----------------------")
	return nil
}

func UpdateForwardParameters(src *pfcp.IEUpdateFAR, dst *pfcp.IECreateFAR) {
	if src.UpdateForwardingPara == nil {
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "FarID(%d) update forwarding parameters is nil ", src.FARID.Value)
		return
	}
	if dst.ForwardingParameters == nil {
		dst.ForwardingParameters = &pfcp.IEForwardingParameters{}
	}
	if src.UpdateForwardingPara.DstInterface != nil {
		dst.ForwardingParameters.DstInterface.Value = src.UpdateForwardingPara.DstInterface.Value
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "FarID(%d) update forwarding parameters,dst interface:%v ",
			src.FARID.Value,
			src.UpdateForwardingPara.DstInterface.Value)
	}

	if src.UpdateForwardingPara.OuterHeaderCreation != nil {
		if dst.ForwardingParameters != nil {
			dst.ForwardingParameters.OuterHeaderCreation = src.UpdateForwardingPara.OuterHeaderCreation
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "FarID(%d) update forwarding parameters,outer header creation:%v ",
				src.FARID.Value, src.UpdateForwardingPara.OuterHeaderCreation)
		} else {
			//dst.ForwardingParameters.TransportLevelMarking = src.UpdateForwardingPara.TransportLevelMarking
			// AN Tunnel Information
			forwardingParameters := &pfcp.IEForwardingParameters{OuterHeaderCreation: &pfcp.IEOuterHeaderCreation{}}
			dst.ForwardingParameters = forwardingParameters

			dst.ForwardingParameters.OuterHeaderCreation = src.UpdateForwardingPara.OuterHeaderCreation
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "FarID(%d) update forwarding parameters,create outer header creation:%v ",
				src.FARID.Value, src.UpdateForwardingPara.OuterHeaderCreation)
		}

	}

	if src.UpdateForwardingPara.NetworkInstance != nil {
		dst.ForwardingParameters.NetworkInstance = src.UpdateForwardingPara.NetworkInstance
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "FarID(%d) update forwarding parameters,network instance:%v ",
			src.FARID.Value, src.UpdateForwardingPara.NetworkInstance)
	}

}

// Update QoS enforcement rule parameters
func UpdateQerParameters(src *pfcp.IEUpdateQER, dst *pfcp.IECreateQER) {
	if src == nil || dst == nil {
		rlogger.Trace(moduleTag, rlogger.WARN, nil, "Update QER parameters is nil")
		return
	}
	//QERID                 IEQERID
	if src.QERID.Value != dst.QERID.Value {
		rlogger.Trace(moduleTag, rlogger.WARN, nil,
			"Update QER parameters,QER ID(%d) does not exist", src.QERID.Value)
		return
	}
	rlogger.Trace(moduleTag, rlogger.INFO, nil,
		"Update QER parameters,QER ID((%d))", src.QERID.Value)
	//	QERCorrelationID      *IEQERCorrelationID
	if src.QERCorrelationID != nil {
		dst.QERCorrelationID = *src.QERCorrelationID
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER parameters,QER correlation ID(%d)", src.QERCorrelationID.Value)
	}
	//	GateStatus            *IEGateStatus
	if src.GateStatus != nil {
		dst.GateStatus = *src.GateStatus
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER parameters,QER gate status(%+v)", src.GateStatus)
	}
	//	MaximumBitrate        *IEMBR
	if src.MaximumBitrate != nil {
		dst.MaximumBitrate = *src.MaximumBitrate
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER parameters,QER maximum bitrate(%+v)", src.MaximumBitrate)
	}
	//	GuaranteedBitrate     *IEGBR
	if src.GuaranteedBitrate != nil {
		dst.GuaranteedBitrate = *src.GuaranteedBitrate
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER parameters,QER guaranteed bitrate(%+v)", src.GuaranteedBitrate)
	}
	//	QoSflowidentifier     *IEQFI
	if src.QoSflowidentifier != nil {
		dst.QoSflowidentifier = *src.QoSflowidentifier
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER parameters,QER QoS flow identifier(%+v)", src.QoSflowidentifier)
	}
	//	ReflectiveQoS         *IERQI
	if src.ReflectiveQoS != nil {
		dst.ReflectiveQoS = *src.ReflectiveQoS
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER parameters,QER reflective QoS(%+v)", src.ReflectiveQoS)
	}
	//	PagingPolicyIndicator *IEPagingPolicyIndicator
	if src.PagingPolicyIndicator != nil {
		dst.PagingPolicyIndicator = *src.PagingPolicyIndicator
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER parameters,QER paging policy indicator(%+v)", src.PagingPolicyIndicator)
	}
	//	AveragingWindow       *IEAveragingWindow
	if src.AveragingWindow != nil {
		dst.AveragingWindow = *src.AveragingWindow
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update QER Parameters,Qer averaging window(%+v)", src.AveragingWindow)
	}
}

func UpdateUrrParameters(src *pfcp.IEUpdateURR, dst *pfcp.IECreateURR) {
	if src == nil || dst == nil {
		rlogger.Trace(moduleTag, rlogger.WARN, nil, "Update N4 session report parameters is nil")
		return
	}
	//URRID                 IEURRID
	if src.URRID.URRIDValue != dst.URRID.URRIDValue {
		rlogger.Trace(moduleTag, rlogger.WARN, nil,
			"Update N4 session  report parameters,N4 report ID(%d) does not exist", src.URRID.URRIDValue)
		return
	}
	rlogger.Trace(moduleTag, rlogger.INFO, nil,
		"Update N4 session report parameters,N4 report ID((%d))", src.URRID.URRIDValue)
	//	MeasurementMethod		*MeasurementMethod
	if src.MeasurementMethod != nil {
		dst.MeasurementMethod = *src.MeasurementMethod
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update N4 session report parameters,N4 session report measurement method(%+v)", src.MeasurementMethod)
	}
	//	ReportingTriggers		*ReportingTriggers
	if src.ReportingTriggers != nil {
		dst.ReportingTriggers = *src.ReportingTriggers
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update N4 session report parameters,N4 session report reporting triggers(%+v)", src.ReportingTriggers)
	}
	//	*VolumeThreshold			*VolumeThreshold
	if src.VolumeThreshold != nil {
		*dst.VolumeThreshold = *src.VolumeThreshold
		rlogger.Trace(moduleTag, rlogger.INFO, nil,
			"Update N4 session report parameters,N4 session report volume threshold(%+v)", src.VolumeThreshold)
	}
}

func SendBufferMsg(n4Cxt *n4context.N4SessionContext) bool {
	rlogger.FuncEntry(moduleTag, utils2.Seid(n4Cxt.SEID))
	l := n4Cxt.Buffer
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "send buffer msg len:%d ", l.Len())
	i := 0
	for e := l.Front(); e != nil; e = e.Next() {
		// fmt.Println(e.Value)
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "%d send buffer msg:%v ", i, e.Value)
		i++
		select {
		case UpfN4Layer.BufferMsg <- e.Value.([]byte):
			return true
		default:
			return false //队列已满，消息丢弃
		}
	}
	n4Cxt.Buffer = list.New()
	return true
}
func SendBufferMsgObstructive(l *list.List) bool {
	rlogger.FuncEntry(moduleTag, nil)
	rlogger.Trace(moduleTag, rlogger.INFO, nil, "Send buffer msg list len:%d ", l.Len())
	i := 0
	for e := l.Front(); e != nil; e = e.Next() {
		// fmt.Println(e.Value)
		rlogger.Trace(moduleTag, rlogger.INFO, nil, "%d send buffer msg", i)
		i++
		select {
		case UpfN4Layer.BufferMsg <- e.Value.([]byte):
			rlogger.Trace(moduleTag, rlogger.INFO, nil, "Send buffer msg value:%#x ", e.Value.([]byte))

		}
	}

	return true
}

// 作为client时，发起N4请求
// N4 Data Notification --> PFCP Session Report Request
func N4SessionReportRequest(n4Ctxt *n4context.N4SessionContext, dfCxt *pdrcontext.DataFlowContext) error {
	rlogger.FuncEntry(moduleTag, utils2.Seid(n4Ctxt.SEID))

	/*// get N4 context
	n4Ctxt, err := upfcontext.GetN4Context(upfcontext.N4SessionIDKey(dfCxt.SEID))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,  "Failure to get N4 Context:%s", err)
		// 本地无上下文，返回成功
		return nil
	}*/

	// 2.	The UPF sends an N4 session Report request message to the SMF.
	//*pfcp.SessionReleaseRequest
	reqN4, err := CreateN4ReportRequestMsg(n4Ctxt, dfCxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Ctxt.SEID), "Failed to create N4 session report request message :%s", err)
		return err
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Ctxt.SEID), "Success to create N4 session report request message :%s", err)
	// 3 发送请求消息，同步处理响应
	var resN4 pfcp.SessionReportResponse
	upfIpN4Port := n4Ctxt.SmfSEID.IPv4Addr.String() + ":" + strconv.Itoa(configure.UpfConf.N4.Smf.Port) //":8806" //127.0.0.1
	err = SendN4MsgI(*reqN4, &resN4, upfIpN4Port)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Ctxt.SEID), "Failed to send N4 message:%s", err)
		return err
	}
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Ctxt.SEID), "Send N4 report request message to :%s", upfIpN4Port)
	// 4 响应成功,SMF响应失败消息
	if resN4.IE.Cause.CauseValue != pfcp.Cause_Request_accepted {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to Report N4 context,cause=%d", resN4.IE.Cause.CauseValue)
		return fmt.Errorf("Failed to Report N4 context,cause=%d", resN4.IE.Cause.CauseValue)
	}
	/*//1.	SMF receives the trigger to remove the N4 session context for the PDU Session.
	// delete N4 context
	// 在upf成功响应后释放本地 N4 context
	err = smfcontext.DeleteN4Context(smfcontext.N4SessionIDKey(seid))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil,  "Failure to delete N4 Context:%s", err)
		return err
	}*/

	// 返回成功
	rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Ctxt.SEID), "Success to send N4 report request message ")
	return nil
}

// IEsSessionReportRequest
func CreateN4ReportRequestMsg(n4Ctxt *n4context.N4SessionContext,
	dfCxt *pdrcontext.DataFlowContext) (*pfcp.SessionReportRequest, error) {
	rlogger.FuncEntry(moduleTag, utils2.Seid(n4Ctxt.SEID))
	var reqN4 pfcp.SessionReportRequest
	// 获取UPF的SEID
	reqN4.PfcpHeader.Set()
	reqN4.PfcpHeader.MessageType = pfcp.PFCP_Session_Report_Request
	reqN4.PfcpHeader.SEID = n4Ctxt.SmfSEID.SEID
	reqN4.PfcpHeader.SequenceNumber = SequenceNumber
	SequenceNumber += 1

	// 2 请求消息构造
	reqN4.IE = pfcp.IEsSessionReportRequest{}
	// todo
	reqN4.IE.ReportType.Set(pfcp.DLDR)

	reqN4.IE.DownlinkDataReport = &pfcp.IEDownlinkDataReport{}
	reqN4.IE.DownlinkDataReport.Set()
	reqN4.IE.DownlinkDataReport.PDRID.Set(dfCxt.RuleID)

	reqN4.IE.DownlinkDataReport.DLDataServiceInfo.Set()

	reqN4.IE.DownlinkDataReport.DLDataServiceInfo.QFI = dfCxt.DP.QFI
	reqN4.IE.DownlinkDataReport.DLDataServiceInfo.Flag &= pfcp.QFII_Flag

	if utils.IsSetByte(dfCxt.DP.PPP, 7) { // todo 定义7
		reqN4.IE.DownlinkDataReport.DLDataServiceInfo.PPIValue = dfCxt.DP.PPI
		reqN4.IE.DownlinkDataReport.DLDataServiceInfo.Flag &= pfcp.PPI_Flag
	}

	return &reqN4, nil
}

func SendN4MsgI(reqN4 interface{}, resN4 interface{}, ipPort string) error {
	rlogger.FuncEntry(moduleTag, nil)
	conn, err := jsonrpc.Dial("TCP", ipPort)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Sent N4 message dailing TCP error: %+v", err)
		return err
	}
	defer conn.Close()

	var serviceMethod string
	switch reqN4.(type) {
	case pfcp.SessionReportRequest:
		serviceMethod = "N4 msg session report request"
		//fmt.Println("N4Msg.SessionModifyRequest")
	default:
		serviceMethod = "N4 msg session report request"
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Service method error")
		return nil
	}

	SessionCall := conn.Go(serviceMethod, reqN4, resN4, nil)
	//fmt.Printf("SessionReleaseResponse：%s\n", resN4.Str)
	//time.Sleep(1*time.Second)
	//fmt.Printf("SessionReleaseResponse：%s\n", resN4.Str)
	// 等待响应
	SessionCall = <-SessionCall.Done
	if SessionCall.Error != nil {
		fmt.Printf("Add: expected no error but got string %q",
			SessionCall.Error.Error())
		return nil
	}
	//fmt.Printf("SessionModifyResponse: %+v\n", resN4)

	return nil
}

func N4SessionDeactivationBuffering(buf []byte, dfCxt *pdrcontext.DataFlowContext) error {
	rlogger.FuncEntry(moduleTag, utils2.Seid(dfCxt.SEID))

	// get N4 context
	n4Ctxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(dfCxt.SEID))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failure to get N4 context:%s", err)
		// 本地无上下文，返回成功
		return nil
	}
	if n4Ctxt.BAR == nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Ctxt.SEID), "Discard messages when the buffer capacity set nil")
		return nil
	}
	if n4Ctxt.Buffer.Len() < int(n4Ctxt.BAR.SugBuffPacketsCount.CountValue) {
		n4Ctxt.Buffer.PushBack(buf)
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Ctxt.SEID), "Current buffer length:%d", n4Ctxt.Buffer.Len())
	} else {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Ctxt.SEID), "Current buffer length  %d", int(n4Ctxt.BAR.SugBuffPacketsCount.CountValue))
		return nil
	}
	// 如果是第一个下行数据到达，则通知SMF
	if n4Ctxt.Buffer.Len() == 1 && n4Ctxt.BufferState {
		// 发送DL数据到达通知给SMF
		//N4SessionReportRequest(n4Ctxt, dfCxt)
		delay := time.Millisecond * time.Duration(n4Ctxt.BAR.DLDataNotificationDelay.Value*50) // 单位是50ms
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Ctxt.SEID), "Current delay:%d", delay)
		if delay == 0 {
			SessionReportRequest(n4Ctxt, dfCxt)
		} else {
			//todo 并发高是goroutie会高。
			time.AfterFunc(delay, func() {
				SessionReportRequest(n4Ctxt, dfCxt)
			})
		}
	}

	return nil
}

func ExceptionSessionRelease(n4Ctxt *n4context.N4SessionContext) error {
	rlogger.FuncEntry(moduleTag, n4context.N4SessionIDKey(n4Ctxt.SEID))

	// 读取当前上下文
	n4Cxt, err := n4context.GetN4Context(n4context.N4SessionIDKey(n4Ctxt.SEID))
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to get N4 Context:%s", err)
		return err
	}

	// N4 Session Release Response
	// todo meter release
	err = metrics.SessionMeterRelease(n4Cxt.MetricItems)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Release upf context counter failed:%s", err)
		//return nil
	} else {
		rlogger.Trace(moduleTag, rlogger.INFO, utils2.Seid(n4Cxt.SEID), "Release upf context counter success:%s", err)
	}
	err = metrics.SessionMeterRelease(n4Cxt.MetricItemsSnapshot)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "release upf context counter snapshot failed:%s", err)
		//return nil
	} else {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "release upf context counter snapshot success:%s", err)
	}

	//3.	The UPF identifies the N4 session context to be removed by the N4 Session ID and removes the whole session context.
	//The UPF responds with an N4 session release response message containing any information that the UPF has to provide to the SMF.
	// 释放会话,删除上下文
	err = n4context.DeleteN4Context(n4context.N4SessionIDKey(n4Cxt.SEID), n4Cxt)
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Failed to delete N4 context:%s", err)
	} else {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Success to delete N4 context:%s", err)
	}
	// delete PDR Table
	err = pdr.DeleteMatchPDRsTable(n4Cxt) // 1.1版本更新  DeleteMatchPDRsTable(n4Cxt) // 1.0 版本
	if err != nil {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Failed to delete match PDRs table:%s", err)
	} else {
		rlogger.Trace(moduleTag, rlogger.ERROR, utils2.Seid(n4Cxt.SEID), "Success to delete match PDRs table:%s", err)
	}

	return nil
}
