package user

import (
	"sync"
	"upf/internal/pkg/rule"
)

type User struct {
	//ids include seid  teid  and ueip
	ids map[string]struct{}
	m   sync.Mutex
	//user info
	rule.ULRule

	rule.DLRule
}

type Users struct {
	users sync.Map
}
