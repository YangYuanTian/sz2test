package main

import (
	"flag"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"syscall"
	"time"
)

var (
	pcapFile      string
	interfaceName string

	log = glog.New()
	ctx = gctx.New()
)

func init() {
	flag.StringVar(&pcapFile, "pfile", "", "send packet use pcap file")
	flag.StringVar(&pcapFile, "interfaceName", "", "send packet use interface Name")
}

func main() {

	handle, err := pcap.OpenOffline(pcapFile)

	if err != nil {
		log.Errorf(ctx, "open offline file failed:%+v\n", err)
	}

	err = handle.SetBPFFilter("ip.addr == 172.20.0.40")
	if err != nil {
		log.Debugf(ctx, "set filter failed:%+v\n", err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle,
		handle.LinkType())

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	if err != nil {
		log.Errorf(ctx, "create socket failed:+v\n", err)
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

	for {
		select {
		case <-ticker.C:
			pkt := <-packetSource.Packets()

			ip := pkt.Layer(layers.LayerTypeIPv4)
			if ip == nil {
				log.Infof(ctx, "nof find ip layer")
				continue
			}

			v4 := ip.(*layers.IPv4)

			ip4 := [4]byte{v4.DstIP[0], v4.DstIP[1], v4.DstIP[2], v4.DstIP[3]}
			dstAddr.Addr = ip4

			err = syscall.Sendto(fd, pkt.Data()[14:], 0, &dstAddr)
		}
	}
}
