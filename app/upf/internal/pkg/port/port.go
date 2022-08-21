// Package port  will receive packet from port
//then dispatch them to different handler,
//and send packet using config port
package port

import (
	"context"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/os/glog"
	"net"
	"sync"
	"syscall"
)

var log = glog.New()

type MsgHandler interface {
	MsgHandle(msg []byte) error
}

type packetType uint8

const (
	arpNeighNotFound packetType = iota + 1
	findRule
	gTPSignalling
)

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
	if config.UserRuler == nil {
		return nil, gerror.New("user ruler shouldn't be nil")
	}

	//check	port exist
	if _, err := net.InterfaceByName(config.InterfaceName); err != nil {
		return nil, gerror.Wrap(err, "interface not exist")
	}

	p := &Port{
		InterfaceType: config.InterfaceType,
		InterfaceName: config.InterfaceName,
		GTPServer:     config.GTPServer,
		UserRuler:     config.UserRuler,
	}

	return p, nil
}

type InterfaceType string

const (
	N3 InterfaceType = "n3"
	N6 InterfaceType = "n6"
)

type Config struct {
	InterfaceType InterfaceType
	InterfaceName string
	GTPServer     MsgHandler
	UserRuler     MsgHandler
}

type ports struct {
	ps map[int]*Port
	m  sync.Mutex
}

var allPorts = &ports{
	ps: make(map[int]*Port),
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

type Port struct {
	InterfaceType InterfaceType
	InterfaceName string

	GTPServer MsgHandler
	UserRuler MsgHandler

	fd              int
	index           int
	receivedPackets chan Packet
}

var ETH_P_IP_SWAPPED = 0x0008

func (p *Port) Run(ctx context.Context) error {

	fd, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_RAW, ETH_P_IP_SWAPPED)

	if err != nil {
		return gerror.Newf("open socket failed for %s", err)
	}

	p.fd = fd

	iface, err := net.InterfaceByName(p.InterfaceName)
	if err != nil {
		return gerror.Newf("get interface failed for %s", err)
	}

	p.index = iface.Index

	//bind to interface
	if err := syscall.BindToDevice(fd, p.InterfaceName); err != nil {
		return gerror.Newf("bind to device failed for %s", err)
	}

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
			}
		}
	}()
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

func (p *Port) worker(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-p.receivedPackets:
			//dispatch packet to different handler
			if p.InterfaceType == N3 {

				if len(packet) < 14 {
					log.Error(ctx, "packet too short")
					continue
				}

				switch packetType(packet[0]) {
				case arpNeighNotFound:

				case gTPSignalling:
					if err := p.GTPServer.MsgHandle(packet); err != nil {
						log.Error(ctx, err)
					}
				case findRule:
				default:
					log.Error(ctx, "unknown packet type")
				}

			} else {
				if err := p.UserRuler.MsgHandle(packet); err != nil {
					log.Error(ctx, err)
				}
			}
		}
	}
}
