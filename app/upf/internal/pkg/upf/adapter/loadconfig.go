/*
* Copyright(C),2020‐2022
* Author: zoujun
* Date: 12/9/20 3:02 PM
* Description:
 */
package adapter

import (
	"fmt"
	"lite5gc/cmn/message/gtpv1u"
	pfcpv1 "lite5gc/cmn/message/pfcp/v1"
	logger "lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/oam/cm/yaml"
	"net"
	"strconv"
	"strings"
	"time"
)

func LoadConfigUPF(confFile string) error {
	//load upf config
	err := yaml.Load(confFile, &configure.CmUpfConf)
	if err != nil {
		return err
	}

	//load version information
	configure.UpfConf.Version = configure.CmUpfConf.Version
	if len(configure.UpfConf.Version.Main) == 0 {
		configure.UpfConf.Version.Main = "0.0.0"
	}

	if len(configure.UpfConf.Version.Patch) == 0 {
		configure.UpfConf.Version.Patch = "999"
	}

	//load logger information
	configure.UpfConf.Logger = configure.CmUpfConf.Logger
	if len(configure.UpfConf.Logger.Level) == 0 {
		configure.UpfConf.Logger.Level = "debug"
	}

	if len(configure.UpfConf.Logger.Path) == 0 {
		configure.UpfConf.Logger.Path = "log/upf.log"
	}

	// load packet capture
	configure.UpfConf.PacketCapture = make([]configure.PktCapInfo, len(configure.CmUpfConf.PacketCapture))
	for i := 0; i < len(configure.CmUpfConf.PacketCapture); i++ {
		configure.UpfConf.PacketCapture[i].Recv = configure.CmUpfConf.PacketCapture[i].Recv
		configure.UpfConf.PacketCapture[i].Send = configure.CmUpfConf.PacketCapture[i].Recv
		configure.UpfConf.PacketCapture[i].PortId = configure.CmUpfConf.PacketCapture[i].PortId
		configure.UpfConf.PacketCapture[i].OutDir = configure.CmUpfConf.PacketCapture[i].OutDir
		configure.UpfConf.PacketCapture[i].PoolCoeff = configure.CmUpfConf.PacketCapture[i].PoolCoeff
	}
	//configure.UpfConf.PacketCapture = configure.CmUpfConf.PacketCapture

	if len(configure.UpfConf.PacketCapture) == 0 {
		for i := 0; i < 2; i++ {
			pktCap := configure.PktCapInfo{false, false, "/home/sde/tmp/", 1, i}
			configure.UpfConf.PacketCapture = append(configure.UpfConf.PacketCapture, pktCap)
		}
	}
	// load N3 configuration
	configure.UpfConf.N3 = configure.CmUpfConf.IpConf.N3
	if len(configure.UpfConf.N3.Ipv4) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N3 ip from config file, set to default.")
		configure.UpfConf.N3.Ipv4 = "127.0.0.1"
	}
	if len(configure.UpfConf.N3.Mask) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil, "load N3 ip mask from config file, set to default.")
		configure.UpfConf.N3.Mask = "255.255.255.255"
	}
	if len(configure.UpfConf.N3.Ipv6) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N3 ipv6  from config file, set to default.")
		configure.UpfConf.N3.Ipv6 = "0:0:0:0:0:0:0:1"
	}
	if len(configure.UpfConf.N3.Ipv6Mask) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil, "load N3 ipv6 mask from config file, set to default.")
		configure.UpfConf.N3.Ipv6Mask = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
	}
	// load N4 configuration
	configure.UpfConf.N4 = configure.CmUpfConf.N4
	if len(configure.UpfConf.N4.Local.Ipv4) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4 local ip from config file, set to default.")
		configure.UpfConf.N4.Local.Ipv4 = "127.0.0.2"
	}

	if configure.UpfConf.N4.Local.Port == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4 local port from config file, set to default.")
		configure.UpfConf.N4.Local.Port = 8805
	}

	// load N4Gtp configuration
	configure.UpfConf.N4Gtp = configure.CmUpfConf.N4Gtp
	if len(configure.UpfConf.N4Gtp.Local.Ipv4) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4Gtp local ip from config file, set to default.")
		configure.UpfConf.N4Gtp.Local.Ipv4 = "127.0.0.2"
	}

	if configure.UpfConf.N4Gtp.Local.Port == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4Gtp local port from config file, set to default.")
		configure.CmUpfConf.N4Gtp.Local.Port = 2152
	}

	// N4 smf configuration
	if len(configure.UpfConf.N4.Smf.Ipv4) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4 SMF ip from config file, set to default.")
		configure.UpfConf.N4.Smf.Ipv4 = "127.0.0.1"
	}

	if configure.UpfConf.N4.Smf.Port == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4 SMF port from config file, set to default.")
		configure.UpfConf.N4.Smf.Port = 8805
	}

	// N4Gtp smf configuration
	if len(configure.UpfConf.N4Gtp.Smf.Ipv4) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4Gtp SMF ip from config file, set to default.")
		configure.UpfConf.N4Gtp.Smf.Ipv4 = "127.0.0.1"
	}

	if configure.UpfConf.N4Gtp.Smf.Port == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N4Gtp SMF port from config file, set to default.")
		configure.UpfConf.N4Gtp.Smf.Port = 2152
	}

	// dnn n6 config
	configure.UpfConf.N6 = configure.CmUpfConf.IpConf.N6
	if len(configure.UpfConf.N6.Ipv4) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N6 ip from config file, set to default.")
		configure.UpfConf.N6.Ipv4 = "127.0.0.1"
	}
	if configure.CmUpfConf.IpConf.N6.MTU == 0 {
		configure.CmUpfConf.IpConf.N6.MTU = 1420
		configure.UpfConf.N6.MTU = 1420
	}
	if len(configure.UpfConf.N6.Mask) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil, "load N6 ip mask from config file, set to default.")
		configure.UpfConf.N6.Mask = "255.255.255.255"
	}
	if len(configure.UpfConf.N6.Ipv6) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N6 ipv6 from config file, set to default.")
		configure.UpfConf.N6.Ipv6 = "0:0:0:0:0:0:0:1"
	}
	if len(configure.UpfConf.N6.Ipv6Mask) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil, "load N6 ipv6 mask from config file, set to default.")
		configure.UpfConf.N6.Ipv6Mask = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
	}
	// nff config
	configure.UpfConf.Nff = configure.CmUpfConf.Nff
	if len(configure.UpfConf.Nff.DpdkArgs) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil, "Failed to load nff dpdk args from config file, set to default.")
		configure.UpfConf.Nff.DpdkArgs = "--log-level=7"
	}

	if len(configure.UpfConf.Nff.StatsServerAddress) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil,
			"load nff stats server address from config file, set to default.")
		configure.UpfConf.Nff.StatsServerAddress = "0.0.0.0"
	}
	if (configure.UpfConf.Nff.StatsServerPort) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil,
			"load nff stats server port from config file, set to default.")
		configure.UpfConf.Nff.StatsServerPort = 8080
	}
	if len(configure.UpfConf.Nff.PowerMode) == 0 {
		configure.UpfConf.Nff.PowerMode = configure.EmptyPolling
		logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil,
			"select power mode %s", configure.EmptyPolling)
	} else {
		if configure.UpfConf.Nff.PowerMode != configure.Interrupt && configure.UpfConf.Nff.PowerMode != configure.Frequency && configure.UpfConf.Nff.PowerMode != configure.Mixed {
			logger.Trace(types.ModuleUpfAdapter, logger.INFO, nil,
				"no such power mode %s,auto select to empty polling", configure.UpfConf.Nff.PowerMode)
			configure.UpfConf.Nff.PowerMode = configure.EmptyPolling
		}
	}
	// dnn_name_gw_ip_map
	// init config
	configure.UpfConf.DnnInfo = make([]configure.DNNInformation, len(configure.CmUpfConf.DnnInfo))
	for i := 0; i < len(configure.UpfConf.DnnInfo); i++ {
		configure.UpfConf.DnnInfo[i].Dnn = configure.CmUpfConf.DnnInfo[i].Dnn
		configure.UpfConf.DnnInfo[i].DnnIp = configure.CmUpfConf.DnnInfo[i].DnnIp
		configure.UpfConf.DnnInfo[i].DnnIpv6 = configure.CmUpfConf.DnnInfo[i].DnnIpv6
		configure.UpfConf.DnnInfo[i].DnnNameIpRangeString = configure.CmUpfConf.DnnInfo[i].DnnNameIpRangeString
		configure.UpfConf.DnnInfo[i].DnnSnssaiUpfIpString = configure.CmUpfConf.DnnInfo[i].DnnSnssaiUpfIpString
	}

	//configure.UpfConf.DnnInfo = configure.CmUpfConf.DnnInfo

	configure.UpfConf.DnnNameGwIpMap = make(map[string]string)
	configure.UpfConf.DnnNameGwIpv6Map = make(map[string]string)
	if len(configure.UpfConf.DnnInfo) == 0 {
		logger.Trace(types.ModuleUpfAdapter, logger.ERROR, nil, "Failed to load N6 dnn gateway ip from config file, set to default.")
		dnn := configure.CmDNNInformation{Dnn: "cmnet", DnnIp: "0.0.0.0", DnnIpv6: "0::0"}
		configure.UpfConf.DnnInfo = append(configure.UpfConf.DnnInfo, configure.DNNInformation{Dnn: dnn.Dnn, DnnIp: dnn.DnnIp,
			DnnIpv6: dnn.DnnIpv6, DnnNameIpRangeString: dnn.DnnNameIpRangeString, DnnSnssaiUpfIpString: dnn.DnnSnssaiUpfIpString})
	}
	loadDnnListToMap(configure.UpfConf.DnnInfo, configure.UpfConf.DnnNameGwIpMap, configure.UpfConf.DnnNameGwIpv6Map)

	// n3 gateway
	configure.UpfConf.N3.Gateway = configure.CmUpfConf.IpConf.N3.Gateway
	if len(configure.UpfConf.N3.Gateway) == 0 {
		configure.UpfConf.N3.Gateway = "0.0.0.0"
	}
	//n6 gateway
	configure.UpfConf.N6.Gateway = configure.CmUpfConf.IpConf.N6.Gateway
	if len(configure.UpfConf.N6.Gateway) == 0 {
		configure.UpfConf.N6.Gateway = "0.0.0.0"
	}
	if len(configure.UpfConf.N6.Ipv6Gw) == 0 {
		configure.UpfConf.N6.Ipv6Gw = "0::0"
	}
	// PM
	configure.UpfConf.Pm = configure.CmUpfConf.Pm
	//huge  page
	configure.UpfConf.HugePage = configure.CmUpfConf.HugePage
	//nic  name
	configure.UpfConf.NicName = configure.CmUpfConf.NicName
	// Timer
	configure.UpfConf.Timer = configure.CmUpfConf.Timer
	pfcpv1.T1 = time.Duration(configure.UpfConf.Timer.Pfcpt1) * time.Second
	gtpv1u.T1 = time.Duration(configure.UpfConf.Timer.Gtput1) * time.Second

	// Kernel         bool
	configure.UpfConf.Kernel = configure.CmUpfConf.Kernel
	configure.UpfConf.StatelessRestart = configure.CmUpfConf.StatelessRestart
	configure.UpfConf.Sbi = configure.CmUpfConf.Sbi

	// Adapter switch
	configure.UpfConf.Adapter = configure.CmUpfConf.Adapter
	if configure.UpfConf.Adapter.GtpuExtheader != 1 {
		// default is 2，Version of the adaptation gNB, 1: Gtpu header 16 bytes; 2: Gtpu header 20 bytes
		configure.UpfConf.Adapter.GtpuExtheader = 2
	}
	configure.UpfConf.Nff.UseKni = configure.CmUpfConf.Nff.UseKni
	configure.UpfConf.Nff.MaxIndex = configure.CmUpfConf.Nff.MaxIndex
	if configure.UpfConf.Nff.MaxIndex == 0 {
		configure.UpfConf.Nff.MaxIndex = 16
	}
	configure.UpfConf.Nff.SchedulerInterval = configure.CmUpfConf.Nff.SchedulerInterval
	if configure.UpfConf.Nff.SchedulerInterval == 0 {
		configure.UpfConf.Nff.SchedulerInterval = 500
	}
	configure.UpfConf.Nff.DisableScheduler = configure.CmUpfConf.Nff.DisableScheduler
	//静态路由配置 根据n6配置的ip与网段，网关生成两条默认路由
	err = ParseN6Route()
	if err != nil {
		fmt.Println("parse n6 route failed:", err)
	}
	//upf profile
	//替换n4 ip地址
	for i, _ := range configure.CmUpfConf.UpfSel {
		configure.CmUpfConf.UpfSel[i].UpfIp = configure.CmUpfConf.N4.Local.Ipv4
	}
	fmt.Println("profile:---------------------------------------")
	fmt.Printf("%+v\n", configure.CmUpfConf.UpfSel)
	configure.UpfConf.UpfSel = configure.CmUpfConf.UpfSel
	return nil
}

func loadDnnListToMap(dnnList []configure.DNNInformation, ipMap, ipv6Map map[string]string) {
	// cmnet,172.16.1.200
	for _, v := range dnnList {
		ipMap[v.Dnn] = v.DnnIp
		ipv6Map[v.Dnn] = v.DnnIpv6
	}
}

// ParseN6Route 解析为标准路由表
func ParseN6Route() error {
	//解析ipv4
	v4 := configure.UpfConf.N6.Ipv4
	mask := configure.UpfConf.N6.Mask
	gw := configure.UpfConf.N6.Gateway
	//解析v4 mask位数 格式类似255.255.0.0
	maskBytes := strings.Split(mask, ".")
	maskBytesV4 := make([]byte, 0, 4)
	for _, value := range maskBytes {
		atoi, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return err
		}
		maskBytesV4 = append(maskBytesV4, byte(atoi))
	}

	ipmask := net.IPv4Mask(maskBytesV4[0], maskBytesV4[1], maskBytesV4[2], maskBytesV4[3])
	ones, bits := ipmask.Size()
	if bits != 32 {
		return fmt.Errorf("not a correct ipv4 mask")
	}
	var route1 string
	var route2 string
	if ones != 32 {
		//基于本地网络生成一条路由 需要配置一条有效的子网掩码，否则不产生配置路由
		route1 = v4 + "/" + strconv.Itoa(ones)
	}
	//基于网关生成一条路由 如果网关为 0.0.0.0 则不配置该路由
	if gw != "" && !strings.Contains(gw, "0.0.0.0") {
		route2 = "0.0.0.0/0 " + gw
	}
	//解析ipv6
	//配置本地网络路由
	v6 := configure.UpfConf.N6.Ipv6
	v6Mask := configure.UpfConf.N6.Ipv6Mask
	v6gw := configure.UpfConf.N6.Ipv6Gw
	var v6route1, v6route2 string
	if v6Mask != "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF" {
		//解析前缀位数
		v6ones := strings.Split(v6Mask, "/")
		if len(v6) < 2 && v6Mask != "" {
			return fmt.Errorf("v6 mask parse error,check fomat :%s", v6Mask)
		}
		atoi, err := strconv.Atoi(v6ones[len(v6ones)-1])
		if err != nil {
			return fmt.Errorf("checkout v6 mask %s:%s", v6Mask, err)
		}
		v6route1 = v6 + "/" + strconv.Itoa(atoi)
	}
	//配置网关路由
	if v6gw != "0::0" {
		v6route2 = "0::0/0  " + v6gw
	}
	fmt.Println(v6route1)
	fmt.Println(v6route2)
	configure.UpfConf.N6route = []string{route1, route2, v6route1, v6route2}
	return nil
}
