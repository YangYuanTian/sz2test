package controller

import (
	"context"
	"github.com/gogf/gf/v2/os/glog"
	"time"
	"upf/internal/pkg/user"
)

var log = glog.New()

type Controller struct {
	Interval time.Duration
	Ctx      context.Context
}

func (c *Controller) Loop() {
	//获取用户的状态数据

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()

	log.Debugf(c.Ctx, user.Print())

	f := func(usr *user.User) error {
		err := usr.ULStat.Refresh()
		if err != nil {
			log.Errorf(c.Ctx, "refresh  user %s error %s", usr.Name(), err)
			return nil
		}

		log.Debugf(c.Ctx, "refresh user %s ul stat success", usr.Name())
		log.Debugf(c.Ctx, "TotalReceivedPackets:%d", usr.ULStat.TotalReceivedPackets)
		log.Debugf(c.Ctx, "TotalReceivedBytes:%d", usr.ULStat.TotalReceivedBytes)
		log.Debugf(c.Ctx, "TotalForwardPackets:%d", usr.ULStat.TotalForwardPackets)
		log.Debugf(c.Ctx, "TotalForwardBytes:%d", usr.ULStat.TotalForwardBytes)

		err = usr.DLStat.Refresh()
		if err != nil {
			log.Errorf(c.Ctx, "refresh user %s error %s", usr.Name(), err)
			return nil
		}

		log.Debugf(c.Ctx, "reflesh user dl stat %s success", usr.Name())
		log.Debugf(c.Ctx, "TotalReceivedPackets:%d", usr.DLStat.TotalReceivedPackets)
		log.Debugf(c.Ctx, "TotalReceivedBytes:%d", usr.DLStat.TotalReceivedBytes)
		log.Debugf(c.Ctx, "TotalForwardPackets:%d", usr.DLStat.TotalForwardPackets)
		log.Debugf(c.Ctx, "TotalForwardBytes:%d", usr.DLStat.TotalForwardBytes)

		return nil
	}

	for {
		select {
		case <-c.Ctx.Done():
			return
		case <-ticker.C:
			log.Debugf(c.Ctx, "print stat data")
			user.Range(f)
		}
	}

	//如果用户的目前的状态和目标的状态一致，那么就不需要做任何事情

	//如果用户的目前的状态和目标的状态不一致，进行一些控制逻辑

}
