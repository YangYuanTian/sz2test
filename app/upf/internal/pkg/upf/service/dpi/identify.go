package dpi

import (
	"encoding/hex"
	"fmt"
	"lite5gc/upf/cp/pdr"
	"strings"

	"github.com/intel-go/nff-go/packet"
)

/*
=================================================================================================================

	函数名: DpiProtoIdentify
	参数：pkt *packet.Packet ---- 报文数据，  appbody []byte ---- 应用数据， fiveTouple *pdr.IpPacketHeaderFields ----
	      报文五元组信息，pktType string ---- 报文类型，tcp、udp或其他
	返回值：bool, string  第一个返回值返回通过信息，第二个返回值返回protocal的类型
	功能：协议识别，识别出协议类型

===================================================================================================================
*/
func DpiProtoIdentify(pkt *packet.Packet, appbody []byte, fiveTouple *pdr.IpPacketHeaderFields, pktType string) (bool, string) {
	var patternStr string

	switch pktType {
	case "tcp":
		patternStr = TcpPattern
	case "udp":
		patternStr = UdpPattern
	default:
		return true, "" //非TCP和UDP报文时，返回结果为通过，采用pdr默认规则匹配处理，如果后续支持该类型报文的过滤，可以单独定义pattern
	}

	patterns, err := GetPatternsFromStr(patternStr)
	if err != nil {
		return true, "" //无法获取正则表达式时，返回结果为通过, 采用pdr默认规则匹配处理
	}

	SetupRegularExps(patterns)
	result, protocolType := filterByPort(fiveTouple)
	if result == false {
		result, protocolType = filterByRegexp(appbody, patterns)
	}

	return result, protocolType
}

/*
===============================================================================================

	函数名: filterByRegexp
	参数：pkt *packet.Packet ---- 报文数据，patterns []Pattern ---- 正则表达式模型切片
	返回值：bool, string  第一个返回值返回是否通过，第二个返回值返回pattern的名字，可以是协议类型等
	功能：根据特征值表达式过滤报文，返回协议类型和是否被过滤

=================================================================================================
*/
func filterByRegexp(appbody []byte, patterns []Pattern) (bool, string) {
	accept := true
	var patternName string

	for _, p := range patterns {
		result := p.Re.MatchString(hex.EncodeToString(appbody))
		if !result {
			continue
		}
		if p.Allow {
			accept = true
			patternName = p.Name
			break
		} else {
			accept = false
			patternName = p.Name
			break
		}
	}

	return accept, patternName
}

/*
==============================================================================================

	函数名: GetUrlFromPkt
	参数：pkt *packet.Packet ---- 报文数据, patternName string ---- pattern的名字，可以是协议类型等
	返回值：url string, err error  第一个返回值返回url, 第二个返回值返回错误信息
	功能：从报文信息中获取url

================================================================================================
*/
func GetUrlFromPkt(pkt *packet.Packet, patternName string) (url string, err error) {
	var tempUrl, tempHost string
	data := pkt.GetRawPacketBytes()

	tempUrl, err = FindMatchStrFromPattern(string(data), UrlPattern, patternName)
	if err != nil {
		return //无法获取正则表达式时，返回错误信息及空的url
	}
	if patternName != "http" {
		splitTempUrl := strings.Split(tempUrl, " ")
		url = splitTempUrl[0]
		return
	}
	splitTempUrl := strings.Split(tempUrl, " ")
	relativeUrl := splitTempUrl[1]

	tempHost, err = FindMatchStrFromPattern(string(data), HostPattern, patternName)
	if err != nil {
		return //无法获取正则表达式时，返回错误信息及空的url
	}
	splitTempHost := strings.Split(tempHost, " ")
	host := strings.TrimRight(splitTempHost[1], "\r\n")
	url = "http://" + host + relativeUrl

	return
}

/*
===================================================================================================

	函数名: FindMatchStrFromPattern
	参数：data string ---- 要匹配的目标字符串数据, pattern string ---- 存放正则表达式模型的字符串,
	     patternName string ---- pattern的名字，可以是协议类型等
	返回值：errors, string  第一个返回值返回错误信息，第二个返回值返回url
	功能：获取从目标字符串中匹配特定pattern的正则表达式的结果

=====================================================================================================
*/
func FindMatchStrFromPattern(data string, pattern string, patternName string) (string, error) {
	var result string

	patterns, err := GetPatternsFromStr(pattern)
	if err != nil {
		return result, err //无法获取正则表达式时，返回错误信息及空的结果
	}
	SetupRegularExps(patterns)

	for _, p := range patterns {
		if p.Name == patternName {
			result = p.Re.FindString(data)
		} else {
			continue
		}
	}
	if result != "" {
		return result, nil
	} else {
		err := fmt.Errorf("get match result failed")
		return result, err
	}
}

/*
===========================================================================================

	函数名: filterByPort
	参数：fiveTouple *pdr.IpPacketHeaderFields  ---- 报文五元组信息
	返回值：result bool, protoType string  第一个返回值返回匹配结果，第二个返回值匹配到的报文类型
	功能：通过端口识别报文类型

==============================================================================================
*/
func filterByPort(fiveTuple *pdr.IpPacketHeaderFields) (result bool, protocolType string) {
	if fiveTuple.SrcPort == 80 || fiveTuple.DstPort == 80 {
		protocolType = "http"
		result = true
	} else if fiveTuple.SrcPort == 53 || fiveTuple.DstPort == 53 {
		protocolType = "dns"
		result = true
	} else if fiveTuple.SrcPort == 554 || fiveTuple.DstPort == 554 {
		protocolType = "rtsp"
		result = true
	} else if fiveTuple.SrcPort == 1883 || fiveTuple.DstPort == 1883 {
		protocolType = "mqtt"
		result = true
	} else if fiveTuple.SrcPort == 20 || fiveTuple.DstPort == 20 || fiveTuple.SrcPort == 21 || fiveTuple.DstPort == 21 {
		protocolType = "ftp"
		result = true
		return
	}

	return
}

/*
===========================================================================================

	函数名: GetDownLinkAppBody
	参数：pkt []byte  ---- 报文信息切片包含传输层首部
	返回值：[]byte, string  报文信息切片不包含传输层首部; 报文类型，tcp、udp或其他
	功能：获取下行报文的应用信息

==============================================================================================
*/
func GetDownLinkAppBody(pkt []byte) ([]byte, string) {
	var pktType string
	appbody := pkt[14:]

	if appbody[9] == 6 { //TCP报文
		appbody = appbody[40:]
		pktType = "tcp"
	} else if appbody[9] == 17 { //UDP报文
		appbody = appbody[28:]
		pktType = "udp"
	} else {
		appbody = nil //其他报文类型时，采用pdr默认规则匹配处理
	}

	return appbody, pktType
}

/*
===========================================================================================

	函数名: GetUpLinkAppBody
	参数：pkt []byte  ---- 报文信息切片包含GTP首部
	返回值：[]byte, string  报文信息切片不包含GTP首部; 报文类型，tcp、udp或其他
	功能：获取上行报文的应用信息

==============================================================================================
*/
func GetUpLinkAppBody(pkt []byte) ([]byte, string) {
	var pktType string
	var appbody []byte

	if pkt[9] == 6 { //TCP报文
		appbody = pkt[40:]
		pktType = "tcp"
	} else if pkt[9] == 17 { //UDP报文
		appbody = pkt[28:]
		pktType = "udp"
	} else {
		appbody = nil //其他报文类型时，采用pdr默认规则匹配处理
	}

	return appbody, pktType
}
