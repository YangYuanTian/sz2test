package user

import (
	"fmt"
	"github.com/cilium/ebpf"
	"sync"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/stat"
)

type User struct {

	//ids include seid  teid  and ueip
	ids map[string]struct{}
	m   sync.Mutex

	UlRuleGetter
	DlRuleGetter

	//user info
	rule.ULRule
	ULStat stat.Stat

	rule.DLRule
	DLStat stat.Stat
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
	users = Users{}
)

func NewUser() *User {
	usr := &User{}

	users.Add(usr)

	return usr
}

func (u *User) AddId(id string) {
	u.m.Lock()
	defer u.m.Unlock()
	u.ids[id] = struct{}{}
	users.Add(u)
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
	u.m.Lock()
	defer u.m.Unlock()

	ids := make([]string, 0, len(u.ids))
	for id := range u.ids {
		ids = append(ids, id)
	}

	return ids
}

type UlRuleGetter interface {
	GetUlRule(*User) *rule.ULRule
}
type DlRuleGetter interface {
	GetDlRule(*User) *rule.DLRule
}

func (u *User) UpdateUlRule() error {

	if u.UlRuleGetter == nil {
		return fmt.Errorf("ul rule getter is nil")
	}

	r := u.UlRuleGetter.GetUlRule(u)
	if r == nil {
		return fmt.Errorf("ul rule is nil")
	}

	u.ULRule = *r

	return u.ULRule.Update(ebpf.UpdateAny)
}

func (u *User) UpdateDlRule() error {
	if u.DlRuleGetter == nil {
		return fmt.Errorf("ul rule getter is nil")
	}

	r := u.DlRuleGetter.GetDlRule(u)
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

func GetUserById(id fmt.Stringer) *User {

	users.m.RLock()
	defer users.m.RUnlock()

	return users.users[id.String()]
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
