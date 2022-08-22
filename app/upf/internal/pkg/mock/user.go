package mock

import (
	"github.com/cilium/ebpf"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/stat"
	"upf/internal/pkg/user"
)

type User struct {
	DlStat *ebpf.Map
	UlStat *ebpf.Map
	UlRule *ebpf.Map
	DlRule *ebpf.Map

	u *user.User
}

func (usr *User) CreateMockUser() *user.User {
	u := &user.User{
		UlRuleGetter: nil,
		DlRuleGetter: nil,
		ULRule: rule.ULRule{
			Map: nil,
			Key: 0,
			Rule: rule.Rule{
				DropForGateControl: false,
				DropForTest:        false,
				PassForTest:        false,
				PassForSample:      false,
				PassForGetRule:     false,
				PassForPaging:      false,
				StatID:             0,
				Desc:               0,
				FlowControl:        0,
				HeaderLen:          0,
			},
		},
		ULStat: stat.Stat{
			Map: nil,
			Key: 0,
		},
		DLRule: rule.DLRule{
			Map: nil,
			Key: 0,
			Rule: rule.Rule{
				DropForGateControl: false,
				DropForTest:        false,
				PassForTest:        false,
				PassForSample:      false,
				PassForGetRule:     false,
				PassForPaging:      false,
				StatID:             0,
				Desc:               0,
				FlowControl:        0,
				HeaderLen:          0,
			},
			TEID:  0,
			GNBIP: nil,
			SrcIP: nil,
			PPP:   false,
			PPI:   false,
			QFI:   0,
		},
		DLStat: stat.Stat{
			Map: nil,
			Key: 0,
		},
	}
	return u
}
