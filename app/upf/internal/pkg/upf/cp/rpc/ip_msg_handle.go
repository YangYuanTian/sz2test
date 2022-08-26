package rpc

import (
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/syncmap"
	. "lite5gc/upf/defs"
	"net"
	"strconv"
)

const moduleTag rlogger.ModuleTag = "rpc"

var FuncEntry = rlogger.FuncEntry

// IP port 对应的conn， key：IP +port；value：connMap
var ConnPool syncmap.SyncMap

// 同一个IP port 对应的多个实例,value:*net.UDPConn
//var connMap = make(map[int]*net.UDPConn, DPE_GOROUTINE_NUMBER)

func ConnPoolGet(ip net.IP, port int) (*net.UDPConn, error) {
	// 如果有，直接返回
	dstAddr := &net.UDPAddr{IP: ip, Port: port}
	addrKey := ip.String() + strconv.Itoa(port)
	if connA := ConnPool.Get(addrKey); connA != nil {
		if value, ok := connA.(map[int]*net.UDPConn); ok {
			for _, v := range value {
				return v, nil
			}
		}
	}
	// 没有时，创建一个
	// 多协程并发 优化，增加重用conn对象，减少并发锁
	// 同一个IP port 对应的多个实例,value:*net.UDPConn
	connMap := make(map[int]*net.UDPConn)
	for i := 0; i < DPE_GOROUTINE_NUMBER; i++ {

		srcAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		//dstAddr := &net.UDPAddr{IP: ip, Port: port}
		conn, err := net.DialUDP("udp", srcAddr, dstAddr)
		if err != nil {
			//fmt.Println(err)
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "Failed to get UPD send connection!")
			return nil, err
		}

		connMap[int(i)] = conn
	}

	// 回收conn,随机获取一个清理
	if ConnPool.Length() > CONN_POOL {

		ConnPool.Range(func(key, value interface{}) bool {
			//ConnPool.Get(key)
			valueA, _ := value.(map[int]*net.UDPConn)
			for _, conn := range valueA {
				conn.Close()
			}

			ConnPool.Del(key)

			return false
		})
	}

	ConnPool.Set(addrKey, connMap)

	return connMap[0], nil

}
