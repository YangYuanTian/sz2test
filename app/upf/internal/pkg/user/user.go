package user

import (
	"sync"
	"upf/internal/pkg/rule"
	"upf/internal/pkg/stat"
)

type User struct {
	//ids include seid  teid  and ueip
	ids map[string]struct{}
	m   sync.Mutex
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

type ULHandler struct {
}

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

func GetUserById(id string) *User {
	return users.users[id]
}
