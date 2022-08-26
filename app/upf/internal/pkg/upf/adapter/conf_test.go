/*
* Copyright(C),2020‐2022
* Author: zoujun
* Date: 12/9/20 3:53 PM
* Description:
 */
package adapter

import (
	"fmt"
	"lite5gc/cmn/types/configure"
	"testing"
)

func TestLoadUpfConf(t *testing.T) {
	var upfConfFile string = "../config/cm_upf_conf.yaml"
	LoadConfigUPF(upfConfFile)
	fmt.Println(configure.CmUpfConf)
	fmt.Println(configure.UpfConf)
	fmt.Println(len(configure.UpfConf.DnnNameGwIpMap))
	fmt.Println(len(configure.UpfConf.DnnNameGwIpv6Map))
}
