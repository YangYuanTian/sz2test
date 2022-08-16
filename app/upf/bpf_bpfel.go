// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfConfig struct{ Ipv4Self uint32 }

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *bpfObjects
//     *bpfPrograms
//     *bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	XdpProgFunc  *ebpf.ProgramSpec `ebpf:"xdp_prog_func"`
	XdpProgFunc1 *ebpf.ProgramSpec `ebpf:"xdp_prog_func1"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	CiliumXdpScratch *ebpf.MapSpec `ebpf:"cilium_xdp_scratch"`
	ConfigRoute      *ebpf.MapSpec `ebpf:"config_route"`
	ConfigRoute1     *ebpf.MapSpec `ebpf:"config_route1"`
	XdpStatsMap      *ebpf.MapSpec `ebpf:"xdp_stats_map"`
	XdpStatsMap1     *ebpf.MapSpec `ebpf:"xdp_stats_map1"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	CiliumXdpScratch *ebpf.Map `ebpf:"cilium_xdp_scratch"`
	ConfigRoute      *ebpf.Map `ebpf:"config_route"`
	ConfigRoute1     *ebpf.Map `ebpf:"config_route1"`
	XdpStatsMap      *ebpf.Map `ebpf:"xdp_stats_map"`
	XdpStatsMap1     *ebpf.Map `ebpf:"xdp_stats_map1"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.CiliumXdpScratch,
		m.ConfigRoute,
		m.ConfigRoute1,
		m.XdpStatsMap,
		m.XdpStatsMap1,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	XdpProgFunc  *ebpf.Program `ebpf:"xdp_prog_func"`
	XdpProgFunc1 *ebpf.Program `ebpf:"xdp_prog_func1"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.XdpProgFunc,
		p.XdpProgFunc1,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed bpf_bpfel.o
var _BpfBytes []byte
