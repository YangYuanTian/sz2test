package mock

import (
	"github.com/cilium/ebpf"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/user"
)

type RuleGetter struct {
	Dl *ebpf.Map
	Ul *ebpf.Map
}

func (r *RuleGetter) GetDlRule(usr *user.User) *rule.DLRule {

	return &rule.DLRule{
		Map:   r.Ul,
		Key:   1,
		TEID:  1,
		GNBIP: nil,
		SrcIP: nil,
		PPP:   false,
		PPI:   0,
		QFI:   0,
	}
}

func (r *RuleGetter) GetUlRule(usr *user.User) *rule.ULRule {

	mockIP := []byte{0x01, 0x02, 0x03, 0x04}
	key := uint32(mockIP[0])<<24 + uint32(mockIP[1])<<16 + uint32(mockIP[2])<<8 + uint32(mockIP[3])

	rl := &rule.ULRule{
		Map: r.Ul,
		Key: key,
	}

	return rl
}
