//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c --  -I ../headers

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var iface1 string
var iface2 string

func init() {
	flag.StringVar(&iface1, "iface1", "", "Network interface to attach XDP program to")
	flag.StringVar(&iface2, "iface2", "", "Network interface to attach XDP program to")
}

var g sync.WaitGroup

func main() {

	flag.Parse()

	if iface1 == "" && iface2 == "" {
		log.Fatalf("Please specify a network interface")
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}

	tmp, err := os.MkdirTemp("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		panic(err)
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: tmp,
		},
	}

	if err := loadBpfObjects(&objs, &opts); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	if iface1 != "" {
		g.Add(1)
		go func() {
			defer g.Done()
			attach(iface1, objs.XdpProgFunc, objs.ConfigRoute, objs.XdpStatsMap)
		}()
	}

	if iface2 != "" {
		g.Add(1)
		go func() {
			defer g.Done()
			attach(iface2, objs.XdpProgFunc1, objs.ConfigRoute1, objs.XdpStatsMap1)
		}()
	}

	g.Wait()
}

func printIPConfig(route *ebpf.Map) {
	var key, value uint32
	err := route.Lookup(&key, &value)
	if err != nil {
		fmt.Println("look err", err)
	}
	fmt.Printf("config: key %d ==> value %d\n", key, value)
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

func configMyIpaddress(m *ebpf.Map, nic *net.Interface) error {

	addr, err := nic.Addrs()
	if err != nil {
		return err
	}

	if len(addr) < 1 {
		return errors.New("ip addr not found with" + nic.Name)
	}

	fmt.Println("interface ip is:", addr[0].String())

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

	return m.Put(uint32(0), ipU32)
}

func attach(ifaceName string, prog *ebpf.Program, routeMap *ebpf.Map, statMap *ebpf.Map) {

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %s: %s", ifaceName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})

	defer link.Close()

	err = configMyIpaddress(routeMap, iface)
	if err != nil {
		log.Fatalf("could config my ip: %s", err)
	}

	printIPConfig(routeMap)

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (destination IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(statMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}
