package utils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"lite5gc/upf/sc/pdr"
	"net"
	"syscall"
	"testing"
	"unsafe"
)

func TestAddrIPv4(t *testing.T) {
	dstAddr := syscall.SockaddrInet4{
		Port: 0,
		//Addr: [4]byte{10, 180, 8, 76},
		Addr: [4]byte{10, 180, 9, 244},
	}
	fmt.Printf("%+v\n", dstAddr)
	Ipv4 := "1.18.90.24"
	ip := net.ParseIP(Ipv4)
	if ip == nil {
		return
	}
	var aa []byte
	aa = ip.To4()
	fmt.Printf("aa %+v\n", aa)
	fmt.Printf("%+v\n", []byte(ip[:]))
	dstAddr.Addr[0] = ip[12]
	dstAddr.Addr[1] = ip[13]
	dstAddr.Addr[2] = ip[14]
	dstAddr.Addr[3] = ip[15]
	fmt.Printf("%+v\n", dstAddr)

	ipvv, err := IPv4Byte("1.18.90.25")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%v\n", ipvv)

	var bb [4]byte
	fmt.Printf("1 %p\n", &bb)
	aa = bb[:] // 切片aa使用数组的bb的物理空间
	fmt.Printf("2 %p\n", &aa[0])
	bb = [4]byte{1, 1, 2, 3} // 数组的赋值是值的拷贝
	fmt.Printf("3 %p\n", &bb)
	aa[0] = 111 // 实质是在修改bb数组
	fmt.Printf("bb %v\n", bb)
	/*1 0xc00004c72c
	  2 0xc00004c72c
	  3 0xc00004c72c*/

	copy(dstAddr.Addr[:], aa)
	fmt.Printf("end %+v\n", dstAddr)

}

func TestLen(t *testing.T) {
	pdr1 := pdr.PacketDetectionRule{}
	qer1 := pdr.QoSEnforcementRule{}
	far1 := pdr.ForwardActionRule{}
	qerLen := unsafe.Sizeof(qer1)
	pdrLen2 := unsafe.Sizeof(pdr1)
	farLen2 := unsafe.Sizeof(far1)
	sum := 2 * 2 * (qerLen + pdrLen2 + farLen2)
	sum2 := 2 * 2 * 1000000 * (qerLen + pdrLen2 + farLen2) / 1024 / 1024
	fmt.Println("a rule len: ", sum, "B")
	fmt.Println("100w rule len: ", sum2, "M")

}

// 五元组获取测试
type IpTestData struct {
	packet       string
	ip           IPv4
	port         UDP
	imcpTypeCode ICMPv4TypeCode
}

// SrcIP:net.ParseIP("11.2.3.1",
var ipTestData = []IpTestData{
	{packet: ipudp,
		ip: IPv4{SrcIP: net.ParseIP("11.2.3.1").To4(),
			DstIP:    net.ParseIP("11.2.2.3").To4(),
			Protocol: IPProtocolUDP,
		},
		port: UDP{SrcPort: 2152, DstPort: 2152},
	},
	{packet: iptcp,
		ip: IPv4{SrcIP: net.ParseIP("127.0.0.1").To4(),
			DstIP:    net.ParseIP("127.0.0.1").To4(),
			Protocol: IPProtocolTCP,
		},
		port: UDP{SrcPort: 58841, DstPort: 9000},
	},
	{packet: ipicmp,
		ip: IPv4{SrcIP: net.ParseIP("10.66.72.111").To4(),
			DstIP:    net.ParseIP("64.0.2.65").To4(),
			Protocol: IPProtocolICMPv4,
		},
		port: UDP{SrcPort: 0, DstPort: 0},
	},
}

// ip/udp/gtpu/ip/icmp

const (
	ipudp string = "452800600000400040111f5e0b020301" +
		"0b02020308680868004c1b6530ff003c" +
		"041801554500003c10b000004001d51f" +
		"0a42486f4000024108004b8d000101ce" +
		"6162636465666768696a6b6c6d6e6f70" +
		"71727374757677616263646566676869"

	iptcp = "4500013357854000800600007f000001" +
		"7f000001" +
		"e5d92328ab84a3af440ee2ae50180805" +
		"9a300000"

	ipicmp = "4500003c10b000004001d51f0a42486f" +
		"4000024108004b8d000101ce61626364" +
		"65666768696a6b6c6d6e6f7071727374" +
		"757677616263646566676869"
)

func TestPacketParse(t *testing.T) {

	for _, test := range ipTestData {
		b, err := hex.DecodeString(test.packet)
		if err != nil {
			t.Fatalf("Failed to Decode header: %v", err)
		}
		tuple, err := IpFiveTuple(b)
		if err != nil {
			t.Fatal("Unexpected error during decoding:", err)
		}
		fmt.Println("expect:", tuple.SrcIp, tuple.SrcPort, tuple.DstIp, tuple.DstPort, tuple.Protocol)
		fmt.Println("result:", test.ip.SrcIP, test.port.SrcPort, test.ip.DstIP, test.port.DstPort, test.ip.Protocol)
		if !bytes.Equal(tuple.SrcIp, test.ip.SrcIP) || !bytes.Equal(tuple.DstIp, test.ip.DstIP) {
			t.Fatalf("Ip mismatch.\nGot:\n%#v\nExpected:\n%#v\n", tuple, test.ip)
		}
		if !(tuple.SrcPort == int(test.port.SrcPort)) || !(tuple.DstPort == int(test.port.DstPort)) {
			t.Fatalf("Port mismatch.\nGot:\n%#v\nExpected:\n%#v\n", tuple, test.port)
		}

		//if !reflect.DeepEqual(tuple.SrcIp, test.ip.SrcIP) {
		//	t.Fatalf("Options mismatch.\nGot:\n%#v\nExpected:\n%#v\n", tuple, test.ip)
		//}

	}

}

func TestOpenNetFD(t *testing.T) {
	for i := 0; i < 100; i++ {
		fdTestA(t)

	}

}

func fdTestA(t *testing.T) {
	Fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP) //需要root权限
	//fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP) //test

	if err != nil {
		t.Fatalf("N6 failed to send ip message : %v", err)
		return
	}
	t.Logf("send AF_INET fd : %d", Fd)

	defer syscall.Close(Fd) //todo 需要考虑关闭情况

}

func IpportdistributeNo(ip net.IP, port int) int {
	//rlogger.FuncEntry(moduleTag, nil)
	tmp := int(binary.BigEndian.Uint32(ip.To4()))
	number := (tmp + port) % 8
	return number
}
func TestIpportdistributeNo(t *testing.T) {
	ip := net.ParseIP("10.19.18.107")
	port := 5000
	i := 0
	for i < 10 {
		i++
		port += i
		fmt.Println(IpportdistributeNo(ip, port))

	}
}
