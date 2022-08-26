package main

import (
	"flag"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"syscall"
	"time"
)

var (
	interfaceName string

	log = glog.New()
	ctx = gctx.New()
)

func init() {
	flag.StringVar(&interfaceName, "interfaceName", "ens3", "send packet use interface Name")
}

func main() {

	flag.Parse()

	log.Infof(ctx, "interfaceName:%s", interfaceName)

	v4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{172, 20, 0, 40},
		DstIP:    []byte{10, 55, 7, 2},
	}

	udp := &layers.UDP{
		SrcPort: 2002,
		DstPort: 2003,
	}

	err := udp.SetNetworkLayerForChecksum(v4)

	if err != nil {
		log.Fatalf(ctx, "set network for checksum failed:%+v\n", err)
	}

	var b [64]byte

	data := gopacket.Payload(b[:])

	buf := gopacket.NewSerializeBuffer()

	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(
		buf,
		opt,
		v4,
		udp,
		data,
	)

	if err != nil {
		log.Fatalf(ctx, "packet SerializeLayers failed%+v\n", err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	if err != nil {
		log.Fatalf(ctx, "create socket failed:+v\n", err)
	}

	defer syscall.Close(fd)

	dstAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{10, 18, 1, 138},
	}

	err = syscall.BindToDevice(fd, interfaceName)

	if err != nil {
		log.Errorf(ctx, "%s bind to device error:%+v\n", interfaceName, err)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:

			ip4 := [4]byte{v4.DstIP[0], v4.DstIP[1], v4.DstIP[2], v4.DstIP[3]}

			dstAddr.Addr = ip4

			pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
			log.Infof(ctx, pkt.Dump())

			err = syscall.Sendto(fd, buf.Bytes(), 0, &dstAddr)

			if err != nil {
				log.Fatalf(ctx, "send pakcet err:%+v\n", err)
			}
		}
	}
}
