package controller

import (
	"context"
	"github.com/gogf/gf/v2/os/glog"
	"time"
	"upf/internal/pkg/user"
)

var log = glog.New()

type Controller struct {
	interval time.Duration
	ctx      context.Context
}

func (c *Controller) Loop() {
	//获取用户的状态数据

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	f := func(usr *user.User) error {
		err := usr.ULStat.Reflesh()
		if err != nil {
			log.Errorf(c.ctx, "reflesh user %s error %s", usr.Name(), err)
			return nil
		}

		log.Debugf(c.ctx, "reflesh user %s ul stat success", usr.Name())
		log.Debugf(c.ctx, "TotalReceivedPackets:%d", usr.ULStat.TotalReceivedPackets)
		log.Debugf(c.ctx, "TotalReceivedBytes:%d", usr.ULStat.TotalReceivedBytes)
		log.Debugf(c.ctx, "TotalForwardPackets:%d", usr.ULStat.TotalForwardPackets)
		log.Debugf(c.ctx, "TotalForwardBytes:%d", usr.ULStat.TotalForwardBytes)

		err = usr.DLStat.Reflesh()
		if err != nil {
			log.Errorf(c.ctx, "reflesh user %s error %s", usr.Name(), err)
			return nil
		}

		log.Debugf(c.ctx, "reflesh user dl stat %s success", usr.Name())
		log.Debugf(c.ctx, "TotalReceivedPackets:%d", usr.DLStat.TotalReceivedPackets)
		log.Debugf(c.ctx, "TotalReceivedBytes:%d", usr.DLStat.TotalReceivedBytes)
		log.Debugf(c.ctx, "TotalForwardPackets:%d", usr.DLStat.TotalForwardPackets)
		log.Debugf(c.ctx, "TotalForwardBytes:%d", usr.DLStat.TotalForwardBytes)

		return nil
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			user.Range(f)
		}
	}

	//如果用户的目前的状态和目标的状态一致，那么就不需要做任何事情

	//如果用户的目前的状态和目标的状态不一致，进行一些控制逻辑

}
