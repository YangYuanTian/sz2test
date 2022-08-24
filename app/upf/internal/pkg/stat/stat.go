package stat

import (
	"github.com/cilium/ebpf"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/os/glog"
)

var log = glog.New()

type bpfStatT struct {
	TotalReceivedBytes   uint64
	TotalForwardBytes    uint64
	TotalReceivedPackets uint64
	TotalForwardPackets  uint64
}

type Stat struct {

	//Map type is BPF_MAP_TYPE_PERCPU_ARRAY
	Map *ebpf.Map
	Key uint32

	bpfStatT
}

// Refresh pull data from map
func (s *Stat) Refresh() error {

	var bpfStat []bpfStatT

	err := s.Map.Lookup(&s.Key, &bpfStat)
	if err != nil {
		return err
	}

	if len(bpfStat) == 0 {
		return gerror.Newf(
			"stat not found with key: %d",
			s.Key)
	}
	log.Debugf(nil, "get cores:%d", len(bpfStat))
	for x := 1; x < len(bpfStat); x++ {
		bpfStat[0].TotalReceivedBytes += bpfStat[x].TotalReceivedBytes
		bpfStat[0].TotalForwardBytes += bpfStat[x].TotalForwardBytes
		bpfStat[0].TotalForwardPackets += bpfStat[x].TotalForwardPackets
		bpfStat[0].TotalReceivedPackets += bpfStat[x].TotalReceivedPackets
	}

	s.TotalReceivedBytes = bpfStat[0].TotalReceivedBytes
	s.TotalForwardBytes = bpfStat[0].TotalForwardBytes
	s.TotalForwardPackets = bpfStat[0].TotalForwardPackets
	s.TotalReceivedPackets = bpfStat[0].TotalReceivedPackets

	return nil
}
