/*
* Copyright(C),2020‐2022
* Author: Lenovo
* Date: 2021/3/30 17:38
* Description:
 */
package gnbcontext

import (
	"context"
	"net"
	"time"
)

type NodeTimer struct {
	//echo timer
	T1       *time.Timer        // echo timer
	T1Reset  func()             // echo timer reset
	T1Cancel context.CancelFunc // 关闭echo goroutine
	//echo Retrans timer
	//T1Retrans       *time.Timer
	T1RetransCancel context.CancelFunc // 关闭echo重传

}

// 基站信息
type GnbInfo struct {
	IpType uint16
	Ip     net.UDPAddr
	Start  bool
	// Sequence Number,节点的当前事务编号,初始值为0
	SequenceNumber uint16

	// timer
	NTimer NodeTimer `json:"-"`

	// n4 node id
	N4NodeId string

	Teid uint32 // test guangzhou
}

// 基站表 key ：gnb ip string；value：*GnbInfo

const (
	Type_IPv4_address = 0
	Type_IPv6_address = 1
)
