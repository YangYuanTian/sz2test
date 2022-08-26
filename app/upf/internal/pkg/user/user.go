package user

import (
	"fmt"
	"github.com/cilium/ebpf"
	"strings"
	"sync"
	"upf/internal/pkg/id"
	"upf/internal/pkg/pktinfo"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/stat"
)

type User struct {

	//ids include seid  teid  and ueip
	ids     map[string]struct{}
	m       sync.RWMutex
	once    sync.Once
	deleted bool

	UlRuleGetter
	DlRuleGetter

	//user info
	rule.ULRule
	ULStat stat.Stat

	rule.DLRule
	DLStat stat.Stat
}

func (u *User) SetStatID(id uint16) {
	u.ULRule.StatID = id
	u.ULStat.Key = uint32(id)
	u.DLStat.Key = uint32(id)
	u.DLRule.StatID = id
}

func (u *User) GetStatID() uint16 {
	return u.ULRule.StatID
}

func (u *User) Save() error {
	err := u.ULRule.Update(ebpf.UpdateAny)
	if err != nil {
		return err
	}
	return u.DLRule.Update(ebpf.UpdateAny)
}

type Users struct {
	users map[string]*User
	m     sync.RWMutex
}

func (u *Users) Add(usr *User) {

	u.m.Lock()
	defer u.m.Unlock()

	ids := usr.GetIds()

	for _, id := range ids {
		u.users[id] = usr
	}
}

var (
	users = Users{
		users: make(map[string]*User),
	}
)

type Config struct {
	DlStat *ebpf.Map
	UlStat *ebpf.Map
	UlRule *ebpf.Map
	DlRule *ebpf.Map
	Ids    []string
}

func NewUser(c Config) *User {
	usr := &User{
		ULRule: rule.ULRule{
			Map: c.UlRule,
		},
		ULStat: stat.Stat{
			Map: c.UlStat,
		},
		DLRule: rule.DLRule{
			Map: c.DlRule,
		},
		DLStat: stat.Stat{
			Map: c.DlStat,
		},
	}

	for _, id := range c.Ids {
		usr.AddId(id)
	}

	return usr
}

func Print() string {
	users.m.RLock()
	defer users.m.RUnlock()

	var s strings.Builder
	s.WriteString("display all users:\n")
	for _, u := range users.users {
		s.WriteString(fmt.Sprintf("%v\n", u))
	}
	return s.String()
}

func (u *User) AddId(id string) {

	u.m.Lock()

	defer users.Add(u)
	defer u.m.Unlock()

	u.once.Do(
		func() {
			u.ids = make(map[string]struct{})
		},
	)

	u.ids[id] = struct{}{}
}

func (u *User) DelId(id string) {
	u.m.Lock()
	defer u.m.Unlock()

	users.m.Lock()
	defer users.m.Unlock()

	delete(users.users, id)

	delete(u.ids, id)
}

func (u *User) GetIds() []string {
	u.m.RLock()
	defer u.m.RUnlock()

	ids := make([]string, 0, len(u.ids))
	for id := range u.ids {
		ids = append(ids, id)
	}

	return ids
}

type UlRuleGetter interface {
	GetUlRule(pkt *pktinfo.UlPkt) *rule.ULRule
}

type DlRuleGetter interface {
	GetDlRule(pkt *pktinfo.DlPkt) *rule.DLRule
}

func (u *User) UpdateUlRule(pkt *pktinfo.UlPkt) error {

	if u.UlRuleGetter == nil {
		return fmt.Errorf("ul rule getter is nil")
	}

	r := u.UlRuleGetter.GetUlRule(pkt)
	if r == nil {
		return fmt.Errorf("ul rule is nil")
	}

	u.ULRule = *r

	return u.ULRule.Update(ebpf.UpdateAny)
}

func (u *User) UpdateDlRule(pkt *pktinfo.DlPkt) error {
	if u.DlRuleGetter == nil {
		return fmt.Errorf("ul rule getter is nil")
	}

	r := u.DlRuleGetter.GetDlRule(pkt)
	if r == nil {
		return fmt.Errorf("ul rule is nil")
	}

	u.DLRule = *r

	return u.DLRule.Update(ebpf.UpdateAny)
}

func (u *User) Name() string {
	var name string
	ids := u.GetIds()
	for _, id := range ids {
		name += ":" + id
	}
	return name
}

func GetUserById(id string) *User {

	users.m.RLock()
	defer users.m.RUnlock()

	return users.users[id]
}

func Range(f func(usr *User) error) {
	users.m.RLock()
	defer users.m.RUnlock()

	visited := make(map[*User]bool)

	for _, v := range users.users {
		if visited[v] {
			continue
		}

		visited[v] = true

		if err := f(v); err != nil {
			return
		}
	}
}

// Delete will release user resource for ebpf maps,and not be got by GetUserById
func (u *User) Delete() error {

	u.m.Lock()
	defer u.m.Unlock()

	if u.deleted {
		return nil
	}

	users.m.Lock()
	defer users.m.Unlock()

	for x := range u.ids {
		delete(users.users, x)
	}

	if err := u.DLRule.Map.Delete(u.DLRule.Key); err != nil {
		return err
	}

	if err := u.ULRule.Map.Delete(u.ULRule.Key); err != nil {
		return err
	}

	if err := u.ULStat.Clear(); err != nil {
		return err
	}

	if err := u.DLStat.Clear(); err != nil {
		return err
	}

	id.StatIDReturn(u.GetStatID())

	u.deleted = true

	return nil
}
