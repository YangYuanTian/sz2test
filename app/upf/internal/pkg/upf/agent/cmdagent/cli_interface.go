/*
* Copyright(C),2020‐2022
* Author: lite5gc
* Date: 2021/1/19 17:58
* Description:
 */
package oamagent

import (
	"errors"
	"fmt"
	"github.com/intel-go/nff-go/packet"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/upf/context/ipport"
	"lite5gc/upf/cp/features"
	"lite5gc/upf/metrics"
	"strings"
)

// show upf arp table
func ShowUpfArpTable() ([]packet.ArpTableInfo, error) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	//var arpResults [][]string
	var arpGroup []packet.ArpTableInfo
	for _, v := range ipport.IpPorts {
		result := v.NeighCache.ShowArpTable(v.Index)
		//arpResults = append(arpResults, result)
		arpGroup = append(arpGroup, result...)
	}
	return arpGroup, nil
}

func ShowUpfArpTableV1() (string, error) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	//var arpResults [][]string
	var arpStr string
	for _, v := range ipport.IpPorts {
		result := v.NeighCache.PrintArpTable()
		//arpResults = append(arpResults, result)
		arpStr += fmt.Sprintf("%s \n", result)
	}
	return arpStr, nil
}

// show upf context n6
func ShowUpfContextN3() (*ipport.IpPortShow, error) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	/*var arpStr string
	for _, port := range ipport.IpPorts {
		//arpResults = append(arpResults, result)
		arpStr += fmt.Sprintf("%s \n", port)
	}
	*/
	portId := configure.UpfConf.N3.PortId
	if portId >= len(ipport.IpPorts) {
		return nil, errors.New("N3 port not exist!")
	}
	return ipport.IpPorts[portId].ShowIpPort(), nil
}

// show upf context n6
func ShowUpfContextN6() (*ipport.IpPortShow, error) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	/*var arpStr string
	for _, port := range ipport.IpPorts {
		//arpResults = append(arpResults, result)
		arpStr += fmt.Sprintf("%s \n", port)
	}
	*/
	portId := configure.UpfConf.N6.PortId
	if portId >= len(ipport.IpPorts) {
		return nil, errors.New("N3 port not exist!")
	}
	return ipport.IpPorts[portId].ShowIpPort(), nil
}

// show upf session -seid x
func ShowUpfSessionSeid(seid uint64) (*metrics.UpfSessionInfo, error) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	upfInfo := metrics.UpfSessionInfoGet(seid)
	if upfInfo == nil {
		logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "Session corresponding to SEID(%d) does not exist:", seid)
		return nil, errors.New("Session does not exist!")
	}
	return upfInfo, nil
}

func ShowUpfSessionIp(ip string) (*metrics.UpfSessionInfo, error) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	seid, err := metrics.GetSeidFromIp(ip)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.WARN, nil, "ShowUpfSessionIp,ip:%s,err:%s", ip, err)
		return nil, err
	}
	logger.Trace(types.ModuleUpfAgent, logger.INFO, nil, "ShowUpfSessionIp,ip:%s : seid:%s", ip, seid)
	upfInfo := metrics.UpfSessionInfoGet(seid)
	if upfInfo == nil {
		logger.Trace(types.ModuleUpfAgent, logger.WARN, nil, "Session corresponding to SEID(%d) does not exist:", seid)
		return nil, errors.New("Session does not exist!")
	}
	return upfInfo, nil
}

func ShowUpfSessionTeid(teid uint32) (*metrics.UpfSessionInfo, error) {
	logger.FuncEntry(types.ModuleUpfAgent, nil)
	seid, err := metrics.GetSeidFromTeid(teid)
	if err != nil {
		logger.Trace(types.ModuleUpfAgent, logger.WARN, nil, "ShowUpfSessionTeid,teid:%d,err:%s", teid, err)
		return nil, err
	}
	logger.Trace(types.ModuleUpfAgent, logger.WARN, nil, "ShowUpfSessionIp,teid:%s : seid:%s", teid, seid)
	upfInfo := metrics.UpfSessionInfoGet(seid)
	if upfInfo == nil {
		logger.Trace(types.ModuleUpfAgent, logger.WARN, nil, "Session corresponding to SEID(%d) does not exist:", seid)
		return nil, errors.New("Session does not exist!")
	}
	return upfInfo, nil
}

func SetUpfPfcpFeature(feature string, onOff bool) interface{} {
	feature = strings.ToUpper(feature)
	var TipsInfo interface{}
	switch feature {
	case "HEEU":
		TipsInfo = features.HEEU(onOff)
	case "LOAD":
		TipsInfo = features.LOAD(onOff)
	case "DDND":
		TipsInfo = features.DLDataNotificationDelayModify(onOff)
	case "FTUP":
		TipsInfo = features.FTUP(onOff)
	case "SUSPENDED":
		TipsInfo = features.UPFSUSPENDED(onOff)
	case "OFFLINE":
		TipsInfo = features.OFFLINE(onOff)
	}
	fmt.Println(feature, onOff)
	return TipsInfo
}
