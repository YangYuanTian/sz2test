/*
* Copyright(C),2020‐2022
* Author: Lenovo
* Date: 2021/3/30 17:38
* Description:
 */
package pfcpgnbcontext

// 基站信息
type PfcpGnbInfo struct {
	// n4 node id
	PfcpNodeId string
	// n3 gtp node id
	GnbNodeId string
}

// 基站表 key ：gnb ip string；value：*GnbInfo

const (
	Type_IPv4_address = 0
	Type_IPv6_address = 1
)
