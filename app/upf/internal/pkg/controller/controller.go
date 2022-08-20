package controller

import "time"

type Controller struct {
	interval time.Duration
}

func (c *Controller) Loop() {

	//获取用户的状态数据

	//如果用户的目前的状态和目标的状态一致，那么就不需要做任何事情

	//如果用户的目前的状态和目标的状态不一致，进行一些控制逻辑

}
