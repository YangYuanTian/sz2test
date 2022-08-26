package manager

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/os/glog"
	"github.com/smallnest/rpcx/log"
	"net"
	"upf/internal/pkg/id"
	"upf/internal/pkg/manager/event"
	"upf/internal/pkg/user"
	"upf/internal/pkg/utils"
)

const (
	TypeCreateUser event.Type = iota + 1
	TypeUpdateUser
	TypeDeleteUser
	TypeSetUserUEIP
	TypeSetUserTEID
)

var m standardManager

type Manager interface {
	Commit(e event.Event)
}

func NewManager(config Config) Manager {

	m = standardManager{
		events: make(chan event.Event, 1000),
		ctx:    gctx.New(),
		log:    glog.New(),
	}

	m.DlStat = config.DlStat
	m.UlStat = config.UlStat
	m.UlRule = config.UlRule
	m.DlRule = config.DlRule

	return &m
}

type standardManager struct {
	events chan event.Event
	ctx    context.Context
	log    *glog.Logger

	DlStat *ebpf.Map
	UlStat *ebpf.Map
	UlRule *ebpf.Map
	DlRule *ebpf.Map
}

func (m *standardManager) Commit(event event.Event) {
	m.events <- event
}

func (s *standardManager) doModify() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case e := <-s.events:

			err := s.handle(e)

			if err != nil {
				log.Errorf("handle modify event failed:%+v\n", err)
			}
		}
	}
}

type CreateUser interface {
	CreateUserById(id fmt.Stringer) error
}

type SetUserUEIP interface {
	SetUserUEIP(ip id.UEIP) error
}

type SetUserTEID interface {
	SetUserTEID(t id.TEID) error
}

type myCreateUser struct {
}

type myUEIPSetter struct {
	id id.UEIP
}

func (m *myUEIPSetter) SetUserUEIP(ip id.UEIP) error {
	m.id = ip
	return nil
}

type myTEIDSetter struct {
	teid id.TEID
}

type Config struct {
	DlStat *ebpf.Map
	UlStat *ebpf.Map
	UlRule *ebpf.Map
	DlRule *ebpf.Map
}

func (u myCreateUser) CreateUserById(i fmt.Stringer) error {

	usr := user.NewUser(user.Config{
		DlStat: m.DlStat,
		UlStat: m.UlStat,
		UlRule: m.UlRule,
		DlRule: m.DlRule,
	})

	usr.AddId(i.String())

	s, err := id.GetStatID()

	if err != nil {
		return err
	}

	usr.SetStatID(s)

	return nil
}

func (s *standardManager) handle(e event.Event) (ret error) {

	defer func() {
		if err := recover(); err != nil {
			ret = gerror.Newf("panic unexpected happen:%+v\n", err)
			return
		}
	}()

	switch e.Type() {
	case TypeCreateUser:
		if err := e.Do(myCreateUser{}); err != nil {
			return err
		}
	case TypeUpdateUser:

	case TypeDeleteUser:

	case TypeSetUserTEID:

		usr := user.GetUserById(e.UserName())
		if usr == nil {
			return gerror.Newf("not found user with id:%s", e.UserName())
		}

		u := myTEIDSetter{}

		if err := e.Do(&u); err != nil {
			return err
		}

		usr.ULRule.Key = utils.SwapUint32(uint32(u.teid))
		usr.ULRule.PassForGetRule = true

		if err := usr.ULRule.Update(ebpf.UpdateAny); err != nil {
			return gerror.New(fmt.Sprintf("update rule failed:%+v\n", err))
		}

	case TypeSetUserUEIP:

		usr := user.GetUserById(e.UserName())
		if usr == nil {
			return gerror.Newf("not found user with id:%s", e.UserName())
		}

		u := myUEIPSetter{}

		if err := e.Do(&u); err != nil {
			return err
		}

		usr.DLRule.Key = utils.KeyOfUEIP(net.IP(u.id))
		usr.DLRule.PassForGetRule = true

		if err := usr.DLRule.Update(ebpf.UpdateAny); err != nil {
			return gerror.New(fmt.Sprintf("update rule failed:%+v\n", err))
		}

	default:
		return gerror.Newf("invalid event commit :event type,%d", e.Type())
	}
	return nil
}
