package nfctxt

import (
	"fmt"
	"github.com/antihax/optional"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/nrf/component-base/pkg/client"
	"lite5gc/openapi/Nnrf_AccessToken"
	"lite5gc/openapi/models"
	"time"
)

func RequestToken() {
	localVarOptionals := Nnrf_AccessToken.AccessTokenRequestParamOpts{
		NfType:       optional.NewInterface(models.NfType_UPF), // nfType of service consumer
		TargetNfType: optional.NewInterface(models.NfType_NRF), // nfType of service producer
		//TargetNfInstanceId: optional.NewInterface(producerInstanceId), // nfInstanceId of service producer
		//RequesterPlmn:      optional.NewInterface("{\"mcc\": \"111\",\"mnc\": \"111\"}"), // plmn of service consumer
		//TargetPlmn:         optional.NewInterface("{\"mcc\": \"111\",\"mnc\": \"111\"}"), // plmn of service producer
	}
	NrfUri := fmt.Sprintf("%s://%s:%d", configure.UpfConf.Sbi.Nrf.Scheme,
		configure.UpfConf.Sbi.Nrf.Addr.Ip, configure.UpfConf.Sbi.Nrf.Addr.Port)
	res, err := client.AccessTokenRequest(NrfUri, configure.UpfConf.Service.InstanceId, localVarOptionals)
	if err != nil {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, err)
	}
	if len(res.AccessToken) > 0 {
		UpfContext.OAuthToken = res.AccessToken
		rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "OAuthToken is (%v)", UpfContext.OAuthToken)
	} else {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "OAuthToken is empty")
	}
	if res.ExpiresIn > 0 {
		go func() {
			select {
			case <-time.After(time.Duration(res.ExpiresIn-1) * time.Second):
				rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "timer to get OAuthToken ")
				RequestToken()
			}
		}()
	} else {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "OAuthToken  Expires time is null")
	}
}
