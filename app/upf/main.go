//go:build linux
// +build linux

// This depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/pkg/errors"
	"net"
	"strings"
	"sync"
	"upf/internal/cmd"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c --  -I ../headers

var iface1 string
var iface2 string

func init() {
	flag.StringVar(&iface1, "n3", "", "Network interface to attach XDP program to")
	flag.StringVar(&iface2, "n6", "", "Network interface to attach XDP program to")
}

// 同步等待
var g sync.WaitGroup

var ctx = gctx.New()
var l = glog.New()

const (
	n3Interface   = "n3"
	n6Interface   = "n6"
	n3n6Interface = "n3n6"
)

func main() {
	cmd.Main.Run(ctx)
	xdp()
}

func xdp() {
	flag.Parse()

	if iface1 == "" && iface2 == "" {
		l.Fatalf(ctx, "Please specify a network interface")
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}

	opts := ebpf.CollectionOptions{}

	if err := loadBpfObjects(&objs, &opts); err != nil {
		l.Fatalf(ctx, "loading objects: %+v", err)
	}
	defer objs.Close()

	var isSameInterface bool

	if iface1 == iface2 {
		isSameInterface = true
	}

	if isSameInterface {
		// Attach the XDP program to the network interface.
		g.Add(1)
		go func() {
			go func() {
				defer g.Done()
				attach(iface1, &objs, n3n6Interface)
			}()
		}()
	} else {
		if iface1 != "" {
			g.Add(1)
			go func() {
				defer g.Done()
				attach(iface1, &objs, n3Interface)
			}()
		}

		if iface2 != "" {
			g.Add(1)
			go func() {
				defer g.Done()
				attach(iface2, &objs, n6Interface)
			}()
		}
	}

	g.Wait()
}

func printIPConfig(config *ebpf.Map) {

	var key, value uint32

	iter := config.Iterate()

	for iter.Next(&key, &value) {
		l.Infof(ctx, "config key: %d ===> value: %d", key, value)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key []byte
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := net.IP(key) // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()
}

func configMyIpaddress(m *ebpf.Map, nic *net.Interface, mod string) error {

	var index []uint32

	switch mod {
	case n3Interface:
		index = append(index, 0)
	case n6Interface:
		index = append(index, 1)
	case n3n6Interface:
		index = append(index, 0, 1)
	}

	addr, err := nic.Addrs()
	if err != nil {
		return err
	}

	if len(addr) < 1 {
		return errors.New("ip addr not found with" + nic.Name)
	}

	l.Infof(ctx, "interface ip is:", addr[0].String())

	ipStr := addr[0].String()

	if strings.Contains(ipStr, "/") {
		ipStr = strings.Split(ipStr, "/")[0]
	}

	if strings.Contains(ipStr, ":") {
		ipStr, _, err = net.SplitHostPort(ipStr)
		if err != nil {
			return err
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return errors.New("parse ip failed")
	}

	if ip.To4() == nil {
		return errors.New("not a ipv4 addr")
	}

	ip = ip.To4()

	ipU32 := uint32(ip[3])<<24 | uint32(ip[2])<<16 | uint32(ip[1])<<8 | uint32(ip[0])

	for _, x := range index {
		if err := m.Put(x, ipU32); err != nil {
			return err
		}
	}

	return nil
}

func attach(interfaceName string, c *bpfObjects, mod string) {

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		l.Fatalf(ctx, "lookup network iface %s: %s", interfaceName, err)
	}

	var prog *ebpf.Program
	switch mod {
	case n3Interface:
		prog = c.XdpProgFuncN3
	case n6Interface:
		prog = c.XdpProgFuncN6
	case n3n6Interface:
		prog = c.XdpProgFuncN3n6
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})

	defer link.Close()

	err = configMyIpaddress(c.ConfigPort, iface, mod)
	if err != nil {
		l.Fatalf(ctx, "could config my ip: %s", err)
	}

	printIPConfig(c.ConfigPort)

	l.Infof(ctx, "Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	l.Infof(ctx, "Press Ctrl-C to exit and remove the program")

}
