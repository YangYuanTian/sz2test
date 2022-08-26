package rpc

import (
	"fmt"
	"lite5gc/cmn/types/configure"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"strconv"

	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	. "lite5gc/upf/cp/n4layer"
)

// receive response
// json rpc server 目前实行是TCP， 请求消息的UDP目标端口号应为8805.它是PFCP的注册端口号。
func StartN4Server(Cxt *types.AppContext) error {
	rlogger.FuncEntry(moduleTag, nil)
	// 开启N4监听
	go StartN4Listen(Cxt)

	return nil
}

func StartN4Listen(Cxt *types.AppContext) {
	rlogger.FuncEntry(moduleTag, nil)

	UpfN4Layer.UpfIp = configure.UpfConf.N4.Local.Ipv4
	//UpfN4Layer.BufferMsg = make(chan []byte, buffer_CHAN_CAP)
	// 注册rpc服务模块
	rpc.Register(new(N4Msg))
	n4Ip := configure.UpfConf.N4.Local.Ipv4
	n4Port := configure.UpfConf.N4.Local.Port
	ipAddr := n4Ip + ":" + strconv.Itoa(n4Port)
	lis, err := net.Listen("tcp4", ipAddr) //"10.180.8.236:8805"
	if err != nil {
		fmt.Printf("fatal error: %s", err)
		panic("Failed to start n4 socket server ")
		return

	}

	fmt.Fprintf(os.Stdout, "N4 server start connection %s\n", ipAddr)

	rlogger.Trace(moduleTag, rlogger.INFO, nil, "N4Listen server routine start")
	Cxt.Wg.Add(1)
	defer func() {
		Cxt.Wg.Done()
		rlogger.Trace(moduleTag, rlogger.ERROR, nil, "N4Listen server routine exit")
	}()
	fdClosed := false
	go func() {
		select {
		case <-Cxt.Ctx.Done():
			/// must fdClosed set true first
			fdClosed = true
			lis.Close()
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "N4Listen server monitor routine exit")
			return
		}
	}()

	for {
		conn, err := lis.Accept() // 接收客户端连接请求
		if err != nil {
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "N4Listen server Accept error occur: ", err)
			if fdClosed {
				break
			}
			continue
		}

		go func(conn net.Conn) { // 并发处理客户端请求
			//fmt.Fprintf(os.Stdout, "%s", "new client in coming\n")
			jsonrpc.ServeConn(conn)
		}(conn)
	}

}

// json rpc client

// send request
