package mock

import (
	"github.com/cilium/ebpf"
	"upf/internal/pkg/id"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/stat"
	"upf/internal/pkg/user"
	"upf/internal/pkg/utils"
)

type User struct {
	DlStat *ebpf.Map
	UlStat *ebpf.Map
	UlRule *ebpf.Map
	DlRule *ebpf.Map

	u *user.User
}

type Config struct {
	TEID    uint32
	GNBTEID uint32
	UEIP    []byte
	StatID  uint16
	GNBIP   []byte
	N3IP    []byte
}

func (usr *User) CreateMockUser(c Config) *user.User {

	u := &user.User{
		ULRule: rule.ULRule{
			Map: usr.UlRule,
			Key: utils.SwapUint32(c.TEID),
			Rule: rule.Rule{
				StatID:     c.StatID,
				DescAction: rule.RemoveGTPHeader,
			},
		},
		ULStat: stat.Stat{
			Map: usr.UlStat,
			Key: uint32(c.StatID),
		},
		DLRule: rule.DLRule{
			Map: usr.DlRule,
			Key: utils.KeyOfUEIP(c.UEIP),
			Rule: rule.Rule{
				StatID:     c.StatID,
				DescAction: rule.CreateGTPHeader,
			},
			TEID:  c.GNBTEID,
			GNBIP: c.GNBIP,
			SrcIP: c.N3IP,
			QFI:   1,
		},
		DLStat: stat.Stat{
			Map: usr.DlStat,
			Key: uint32(c.StatID),
		},
	}

	usr.u = u

	u.AddId(id.TEID(c.TEID).String())
	u.AddId(id.UEIP(c.UEIP).String())

	return u
}
