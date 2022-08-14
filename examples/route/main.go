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

import (
	"fmt"
	"github.com/pkg/errors"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf route.c --   -I ../headers/

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
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
	go func() {
		time.Sleep(30 * time.Second)
		os.Exit(-1)
	}()
	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	err = configMyIpaddress(objs.ConfigRoute, iface)
	if err != nil {
		log.Fatalf("could config my ip: %s", err)
	}

	printIPConfig(objs.ConfigRoute)

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpStatsMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
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
