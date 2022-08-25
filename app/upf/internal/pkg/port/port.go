// Package port  will receive packet from port
// then dispatch them to different handler,
// and send packet using config port
package port

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gopcap "github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"upf/internal/pkg/port/pcap"
	"upf/internal/pkg/utils"
)

var log = glog.New()

type MsgHandler interface {
	MsgHandle(ctx context.Context, msg []byte) error
}

type packetType uint8

const (
	arpNeighNotFound packetType = iota + 1
	ulFindRule
	dlFindRule
	gtpSignalling
)

func (t packetType) String() string {
	switch t {
	case arpNeighNotFound:
		return "arpNeighNotFound"
	case dlFindRule:
		return "dlFindRule"
	case ulFindRule:
		return "ulFindRule"
	case gtpSignalling:
		return "gtpSignalling"
	default:
		return "unknown packet type"
	}

}

func NewPort(config *Config) (*Port, error) {

	//type and name check
	if config == nil {
		return nil, gerror.New("config should not be nil")
	}

	//handler check
	if config.InterfaceType == N3 && config.GTPServer == nil {
		return nil, gerror.New(
			"gtp server shouldn't be nil when use n3 port")
	}

	//ruler check
	if config.UlUserRuler == nil && config.InterfaceType == N3 {
		return nil, gerror.New("user ruler shouldn't be nil")
	}

	if config.DlUserRuler == nil && config.InterfaceType == N6 {
		return nil, gerror.New("user ruler shouldn't be nil")
	}

	//check	port exist
	if _, err := net.InterfaceByName(config.InterfaceName); err != nil {
		return nil, gerror.Wrap(err, "interface not exist")
	}

	p := &Port{
		InterfaceType:   config.InterfaceType,
		InterfaceName:   config.InterfaceName,
		GTPServer:       config.GTPServer,
		UlUserRuler:     config.UlUserRuler,
		DlUserRuler:     config.DlUserRuler,
		receivedPackets: make(chan Packet, 10000),
		pcapChan:        make(chan Packet, 10000),
	}

	return p, nil
}

type InterfaceType string

const (
	N3   InterfaceType = "n3"
	N6   InterfaceType = "n6"
	N3N6 InterfaceType = "n3n6"
)

type Config struct {
	InterfaceType InterfaceType
	InterfaceName string
	GTPServer     MsgHandler
	UlUserRuler   MsgHandler
	DlUserRuler   MsgHandler
}

type ports struct {
	ps map[int]*Port
	m  sync.Mutex
}

var allPorts = &ports{
	ps: make(map[int]*Port),
}

func (p *ports) GetPort(index int) (*Port, error) {

	port, ok := p.ps[index]
	if !ok {
		return nil, gerror.New("port not exist")
	}

	return port, nil

}
func (p *ports) addPort(port *Port) error {

	p.m.Lock()
	defer p.m.Unlock()

	_, ok := p.ps[port.index]
	if ok {
		return gerror.New("port already exist")
	}

	p.ps[port.index] = port

	return nil
}

type Packet []byte

func (p Packet) String() string {

	pkt := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	return pkt.Dump()
}

func (p Packet) GetDstIP() (net.Addr, error) {

	pkt := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	ip := pkt.Layer(layers.LayerTypeIPv4)

	if ip == nil {
		return nil, gerror.New("ip layer not found")
	}

	v4 := ip.(*layers.IPv4)

	addr, err := net.ResolveIPAddr("ip4", v4.DstIP.String())
	if err != nil {
		return nil, err
	}

	return addr, nil
}

func (p Packet) GetDstIPByte() ([4]byte, error) {

	pkt := gopacket.NewPacket(p, layers.LayerTypeEthernet, gopacket.Default)

	ip := pkt.Layer(layers.LayerTypeIPv4)

	if ip == nil {
		return [4]byte{}, gerror.New("ip layer not found")
	}

	v4 := ip.(*layers.IPv4)

	return [4]byte{v4.DstIP[0], v4.DstIP[1], v4.DstIP[2], v4.DstIP[3]}, nil
}

type Port struct {
	InterfaceType InterfaceType
	InterfaceName string

	GTPServer   MsgHandler
	UlUserRuler MsgHandler
	DlUserRuler MsgHandler

	fd              int
	index           int
	receivedPackets chan Packet

	setUpPcap bool
	pcapChan  chan Packet
}

var EthPIpSwapped = 0x0008

func (p *Port) Run2(ctx context.Context) error {

	var (
		snapshotLen int32 = 2048
		promiscuous       = false
		timeout           = -1 * time.Second
	)

	handle, err := gopcap.OpenLive(
		p.InterfaceName, snapshotLen, promiscuous, timeout)

	if err != nil {
		return err
	}

	err = handle.SetBPFFilter("ip || arp")
	if err != nil {
		return err
	}

	defer handle.Close()

	// Open output pcap file and write header
	f, _ := os.Create(p.InterfaceName + ".pcap")
	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	defer f.Close()

	packetSource := gopacket.NewPacketSource(handle,
		handle.LinkType())

	iface, err := net.InterfaceByName(p.InterfaceName)

	if err != nil {
		return gerror.Newf("get interface failed for %s", err)
	}

	p.index = iface.Index

	if err := allPorts.addPort(p); err != nil {
		return err
	}

	ip, err := utils.GetNicIpByName(p.InterfaceName)
	if err != nil {
		return err
	}

	conn, err := net.ListenIP("ip:all", &net.IPAddr{
		IP: ip,
	})

	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packetSource.Packets():

			pkt := packet.Data()

			if p.setUpPcap {
				_ = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}

			//dispatch packet to different handler
			if len(pkt) < 14 {
				log.Error(ctx, "packet too short")
				continue
			}

			switch packetType(pkt[0]) {
			case arpNeighNotFound:

				log.Debugf(ctx, "handle arp not found request\n")

				log.Debugf(ctx, "packet info :%s\n", packet)

				if len(pkt) < MacLen {
					log.Error(ctx, "packet too short")
				}

				index := int(pkt[1])

				log.Debugf(ctx, "get index port of %d", index)

				//_, err := allPorts.GetPort(index)
				//if err != nil {
				//	log.Error(ctx, err)
				//	continue
				//}

				_, err = conn.Write(pkt[MacLen:])
				if err != nil {
					log.Fatal(ctx, "Failed to send package,%+v", err)
				}

				if err != nil {
					log.Error(ctx, err)
					continue
				}

			case gtpSignalling:
				if err := p.GTPServer.MsgHandle(ctx, packet.Data()); err != nil {
					log.Error(ctx, err)
				}
			case ulFindRule:
				if err := p.UlUserRuler.MsgHandle(ctx, packet.Data()); err != nil {
					log.Error(ctx, err)
				}
			case dlFindRule:
				if err := p.DlUserRuler.MsgHandle(ctx, packet.Data()); err != nil {
					log.Error(ctx, err)
				}
			default:
			}
		}
	}
}

func (p *Port) Run4(ctx context.Context) error {

	var (
		snapshotLen int32 = 2048
		promiscuous       = false
		timeout           = -1 * time.Second
	)

	handle, err := gopcap.OpenLive(
		p.InterfaceName, snapshotLen, promiscuous, timeout)

	if err != nil {
		return err
	}

	err = handle.SetBPFFilter("ip")
	if err != nil {
		return err
	}

	defer handle.Close()

	// Open output pcap file and write header
	f, _ := os.Create(p.InterfaceName + ".pcap")
	w := pcapgo.NewWriter(f)
	err = w.WriteFileHeader(1024, layers.LinkTypeEthernet)
	defer f.Close()

	packetSource := gopacket.NewPacketSource(handle,
		handle.LinkType())

	iface, err := net.InterfaceByName(p.InterfaceName)

	if err != nil {
		return gerror.Newf("get interface failed for %s", err)
	}

	p.index = iface.Index

	if err := allPorts.addPort(p); err != nil {
		return err
	}

	ip, err := utils.GetNicIpByName(p.InterfaceName)
	if err != nil {
		return err
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)

	if err != nil {
		return err
	}

	defer syscall.Close(fd)

	dstAddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{ip[0], ip[1], ip[2], ip[3]},
	}

	err = syscall.Bind(fd, &dstAddr)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packetSource.Packets():

			pkt := packet.Data()

			if p.setUpPcap {
				_ = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}

			//dispatch packet to different handler
			if len(pkt) < 14 {
				log.Error(ctx, "packet too short")
				continue
			}

			switch packetType(pkt[0]) {
			case arpNeighNotFound:

				log.Debugf(ctx, "handle arp not found request\n")

				log.Debugf(ctx, "packet info :%s\n", packet)

				if len(pkt) < MacLen {
					log.Error(ctx, "packet too short")
				}

				index := int(pkt[1])

				log.Debugf(ctx, "get index port of %d", index)

				//_, err := allPorts.GetPort(index)
				//if err != nil {
				//	log.Error(ctx, err)
				//	continue
				//}

				dstIP, err := Packet(pkt).GetDstIPByte()
				if err != nil {
					log.Errorf(ctx, "failed to get dst ip %+v\n", err)
				}

				dstAddr.Addr = dstIP

				err = syscall.Sendto(fd, pkt[MacLen:], 0, &dstAddr)

				if err != nil {
					log.Fatal(ctx, "Failed to send package,%+v", err)
				}

				if err != nil {
					log.Error(ctx, err)
					continue
				}

			case gtpSignalling:
				if err := p.GTPServer.MsgHandle(ctx, packet.Data()); err != nil {
					log.Error(ctx, err)
				}
			case ulFindRule:
				if err := p.UlUserRuler.MsgHandle(ctx, packet.Data()); err != nil {
					log.Error(ctx, err)
				}
			case dlFindRule:
				if err := p.DlUserRuler.MsgHandle(ctx, packet.Data()); err != nil {
					log.Error(ctx, err)
				}
			default:
			}
		}
	}
}

func (p *Port) Run3(ctx context.Context) error {

	iface, err := net.InterfaceByName(p.InterfaceName)

	if err != nil {
		return gerror.Newf("get interface failed for %s", err)
	}

	p.index = iface.Index

	if err := allPorts.addPort(p); err != nil {
		return err
	}

	ip, err := utils.GetNicIpByName(p.InterfaceName)
	if err != nil {
		return err
	}

	conn, err := net.ListenPacket("ip", ip.String())

	if err != nil {
		return err
	}

	pcap, err := pcap.NewPcap(p.InterfaceName)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:

			var pkt = make([]byte, 2000)

			n, _, err := conn.ReadFrom(pkt)
			if err != nil {
				log.Error(ctx, "read packet error:%+v", err)
				continue
			}

			pkt = pkt[:n]

			if p.setUpPcap {
				_ = pcap.WritePcap(pkt[:n])
			}

			//dispatch packet to different handler
			if len(pkt) < 14 {
				log.Error(ctx, "packet too short")
				continue
			}

			switch packetType(pkt[0]) {
			case arpNeighNotFound:

				log.Debugf(ctx, "handle arp not found request\n")

				log.Debugf(ctx, "packet info :%s\n", Packet(pkt))

				if len(pkt) < MacLen {
					log.Error(ctx, "packet too short")
				}

				index := int(pkt[1])

				log.Debugf(ctx, "get index port of %d", index)

				dstIP, err := Packet(pkt).GetDstIP()
				if err != nil {
					log.Error(ctx, "get dst ip err%+v", err)
				}

				_, err = conn.WriteTo(pkt[MacLen:], dstIP)
				if err != nil {
					log.Fatal(ctx, "Failed to send package,%+v", err)
				}

				if err != nil {
					log.Error(ctx, err)
					continue
				}

			case gtpSignalling:
				if err := p.GTPServer.MsgHandle(ctx, pkt); err != nil {
					log.Error(ctx, err)
				}
			case ulFindRule:
				if err := p.UlUserRuler.MsgHandle(ctx, pkt); err != nil {
					log.Error(ctx, err)
				}
			case dlFindRule:
				if err := p.DlUserRuler.MsgHandle(ctx, pkt); err != nil {
					log.Error(ctx, err)
				}
			default:
			}
		}
	}
}

func (p *Port) Run(ctx context.Context) error {

	//_ := syscall.ETH_P_IP

	fd, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_RAW, 0x0008)

	if err != nil {
		return gerror.Newf("open socket failed for %s", err)
	}

	p.fd = fd

	iface, err := net.InterfaceByName(p.InterfaceName)
	if err != nil {
		return gerror.Newf("get interface failed for %s", err)
	}

	p.index = iface.Index

	if err := allPorts.addPort(p); err != nil {
		return err
	}

	//bind to interface
	if err := syscall.BindToDevice(fd, p.InterfaceName); err != nil {
		return gerror.Newf("bind to device failed for %s", err)
	}

	log.Infof(ctx, "fd %d (type:%s):bind to device %s", fd, p.InterfaceType, p.InterfaceName)
	//receive packets and send to channel
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				buf := make([]byte, 2048)

				n, err := syscall.Read(fd, buf)

				if err != nil {
					log.Error(ctx, err)
					continue
				}

				p.receivedPackets <- buf[:n]

				if p.setUpPcap {
					p.pcapChan <- buf[:n]
				}
			}
		}
	}()

	go p.worker(ctx)

	return nil
}

func (p *Port) Send(msg []byte) error {
	//send packet to port
	_, err := syscall.Write(p.fd, msg)
	return err
}

func (p *Port) Close() error {
	//close port
	return syscall.Close(p.fd)
}

const MacLen = 14

func (p *Port) worker(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-p.receivedPackets:
			//dispatch packet to different handler
			if len(packet) < 14 {
				log.Error(ctx, "packet too short")
				continue
			}

			switch packetType(packet[0]) {
			case arpNeighNotFound:

				log.Debugf(ctx, "handle arp not found request\n")

				log.Debugf(ctx, "packet info :%s\n", packet)

				if len(packet) < MacLen {
					log.Error(ctx, "packet too short")
				}

				index := int(packet[1])

				log.Debugf(ctx, "get index port of %d", index)

				port, err := allPorts.GetPort(index)
				if err != nil {
					log.Error(ctx, err)
					continue
				}

				err = port.Send(packet[MacLen:])

				if err != nil {
					log.Error(ctx, err)
					continue
				}

			case gtpSignalling:
				if err := p.GTPServer.MsgHandle(ctx, packet); err != nil {
					log.Error(ctx, err)
				}
			case ulFindRule:
				if err := p.UlUserRuler.MsgHandle(ctx, packet); err != nil {
					log.Error(ctx, err)
				}
			case dlFindRule:
				if err := p.DlUserRuler.MsgHandle(ctx, packet); err != nil {
					log.Error(ctx, err)
				}
			default:
			}
		}
	}
}

func (p *Port) Pcap(ctx context.Context) error {
	p.setUpPcap = true

	cap, err := pcap.NewPcap(fmt.Sprintf("%s", p.InterfaceName))

	if err != nil {
		return err
	}

	defer cap.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt := <-p.pcapChan:
			if err := cap.WritePcap(pkt); err != nil {
				return err
			}
		}
	}
}
