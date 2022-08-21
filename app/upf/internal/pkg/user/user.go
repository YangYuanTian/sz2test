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
	users sync.Map
}
