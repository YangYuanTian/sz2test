package nfctxt

import (
	"context"
	"fmt"
	"io/ioutil"
	"lite5gc/cmn/redisclt"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/openapi/Nnrf_NFManagement"
	"lite5gc/openapi/models"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Register NFInstance
func SendRegisterNFInstance(nrfUri string, nfInstanceId string, profile models.NfProfile) (resourceNrfUri string,
	retrieveNfInstanceId string, err error) {
	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendRegisterNFInstance nrfUri:%s nfInstanceId:%s ", nrfUri, nfInstanceId)

	var res *http.Response
	for {
		configuration := Nnrf_NFManagement.NewConfiguration()
		configuration.SetBasePath(UpfContext.NrfUri)
		configuration.AddDefaultHeader("authorization", "Bearer"+" "+UpfContext.OAuthToken)
		client := Nnrf_NFManagement.NewAPIClient(configuration)
		_, res, err = client.NFInstanceIDDocumentApi.RegisterNFInstance(context.TODO(), nfInstanceId, profile)
		if err != nil {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF register to NRF Error[%v]", err)
			if AppContext.NfDeregisterFailed(nrfUri) {
				return
			}
			if res != nil {
				if res.StatusCode == 400 {
					rlogger.Trace(types.ModuleSmfSbi, rlogger.ERROR, nil, "Incomplete carrying parameters")
					return
				}
			}
			time.Sleep(3 * time.Second)
			continue
		}
		status := res.StatusCode
		localVarBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendRegisterNFInstance ioutil.ReadAll fail")
		}

		//status == http.StatusOK 		NFUpdate
		//status == http.StatusCreated 	NFRegister
		if status == http.StatusOK || status == http.StatusCreated {
			//get heartBeatTimer interval
			contents := strings.Split(string(localVarBody), ",")
			rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "contents:%s", contents)

			for k, _ := range contents {
				if strings.Contains(contents[k], "heartBeatTimer") {
					comma := strings.Split(contents[k], ":")
					heartBeatTimer2, err := strconv.Atoi(comma[1])
					if err != nil {
						rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendRegisterNFInstance nfInstanceId:%s strconv.Atoi fail", nfInstanceId)
						err = fmt.Errorf("strconv.Atoi failed ,can't find hb")
						continue
					}
					rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "SendRegisterNFInstance nfInstanceId:%s receive heartBeatTimer:%d", nfInstanceId, heartBeatTimer2)
					//start HB with NRF
					UpfContext.HeartBeatSec = time.Duration(heartBeatTimer2)
					if UpfContext.TimerId > 0 {
						go TimerStop(UpfContext.TimerId)
					}
					//HeartBeatTimer
					UpfContext.TimerId = TimerStart(UpfContext.HeartBeatSec, UpfContext.NfId, NfHeartBeatTimer)
					break
				}
			}
			break
		} else {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendRegisterNFInstance nfInstanceId:%s receive wrong status:%d", nfInstanceId, status)
		}
	}

	//cache localVarBody  for UPF need check heartBeatTimer  in localVarHTTPResponse.Body ,release res.Body here
	defer res.Body.Close()

	return resourceNrfUri, retrieveNfInstanceId, err
}

func SendDeregisterNFInstance() (err error) {
	rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "SendDeregisterNFInstance NfInstanceId:%s", UpfContext.NfId)
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(UpfContext.NrfUri)
	configuration.AddDefaultHeader("authorization", "Bearer"+" "+UpfContext.OAuthToken)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response

	res, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(context.Background(), UpfContext.NfId)
	if err != nil || res == nil {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "UPF deregister to NRF Error[%v]", err.Error())
		return
	} else {
		status := res.StatusCode
		//problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		//problemDetails = &problem
		rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "SendDeregisterNFInstance  NfInstanceId:%s done status:%d ", UpfContext.NfId, status)
	}
	return
}

func SendUpdateNFInstance(nrfUri string, nfInstanceId string) (err error) {
	//UpfContext := UPF_AmfContext()

	//3GPP 29510 5.2.2.3.2-1: NF Heart-Beat
	//PATCH .../nf-instances/4947a69a-f61b-4bc1-b9da-47c9c5d14b64
	//Content-Type: application/json-patch+json
	//[
	//  { "op": "replace", "path": "/nfStatus", "value": "REGISTERED" },
	//  { "op": "replace", "path": "/load", "value": 50 }
	//]
	//HTTP/2 204 No Content
	//Content-Location: .../nf-instances/4947a69a-f61b-4bc1-b9da-47c9c5d14b64

	var patchItemList []models.PatchItem

	patchItem := models.PatchItem{
		Op:    models.PatchOperation_REPLACE, //"replace",
		Path:  "/nfStatus",
		Value: "REGISTERED",
	}

	patchItemList = append(patchItemList, patchItem)

	var res *http.Response
	var retryCount = 0
	for {
		configuration := Nnrf_NFManagement.NewConfiguration()
		configuration.SetBasePath(nrfUri)
		configuration.AddDefaultHeader("authorization", "Bearer"+" "+UpfContext.OAuthToken)
		client := Nnrf_NFManagement.NewAPIClient(configuration)

		_, res, err = client.NFInstanceIDDocumentApi.UpdateNFInstance(context.TODO(), nfInstanceId, patchItemList)
		if err != nil || res == nil {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil,
				"UpdateNFInstance UPF nfInstanceId:%s register to NRF error(%v) ", nfInstanceId, err.Error())
			retryCount++
			if retryCount >= 3 {
				rlogger.Trace(types.ModuleAmfSbi, rlogger.ERROR, nil, "UpdateNFInstance   nfInstanceId:%s fail ", nfInstanceId)
				return err
			}
			time.Sleep(2 * time.Second)
			continue
		}

		status := res.StatusCode
		if status < 300 {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.TRACE, nil, "UpdateNFInstance  success,status:%d ", status)
		} else {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UpdateNFInstance  wrong status code :%d", status)
		}
		break
	}

	return err
}

// 3GPP 29510 5.2.2.5 NFStatusSubscribe
// The NF Service Consumer shall send a POST request to the resource URI representing the "subscriptions" collection resource.
func SendNFStatusSubscribe() (err error) {
	// rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendNFStatusSubscribe NfInstanceId:%s", UpfContext.NfId)
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(UpfContext.NrfUri)
	configuration.AddDefaultHeader("authorization", "Bearer"+" "+UpfContext.OAuthToken)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var subscriptionData models.NrfSubscriptionData

	subscriptionData.NfStatusNotificationUri = UpfContext.GetNfStatusNotify()
	subscriptionData.ReqNfInstanceId = UpfContext.NfId
	subscriptionData.ReqNfType = models.NfType_UPF

	SubscriptionId, err := redisclt.Agent.HIncrBy("idMgr", "NrfSubID", 1)
	if err != nil {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "set subscription id error(%v)", err)
		return
	}
	subscriptionData.SubscriptionId = strconv.Itoa(SubscriptionId)

	var res *http.Response
	var respSubscription models.NrfSubscriptionData

	respSubscription, res, err = client.SubscriptionsCollectionApi.CreateSubscription(context.Background(), subscriptionData)
	if err != nil || res == nil {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "UPF NFStatusSubscribe to NRF Error[%v]", err.Error())
		return
	} else {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "SendNFStatusSubscribe NfInstanceId:%s  status:%d SubscriptionId:%s", UpfContext.NfId, res.StatusCode, respSubscription.SubscriptionId)
		if res.StatusCode < 300 {
			//cache Subscription_id
			UpfContext.SubscriptionId = respSubscription.SubscriptionId

			//3GPP 39510 5.2.2.5.2-1: Subscription to NF Instances in the same PLMN
			//On success, "201 Created" shall be returned.
			//The response shall contain the data related to the created subscription,
			//including the validity time, as determined by the NRF, after which the subscription becomes invalid.
			//Once the subscription expires, if the NF Service Consumer wants to keep receiving status notifications,
			//it shall create a new subscription in the NRF.

			//check ValidityTime
			ValidityTime := *respSubscription.ValidityTime
			interval := ValidityTime.Sub(time.Now())
			UpfContext.NfStatusSubs = time.Duration(interval.Seconds())
			if UpfContext.NfStatusSubs > 100 {
				UpfContext.NfStatusSubs = UpfContext.NfStatusSubs - 100
			}

			rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendNFStatusSubscribe NfInstanceId:[%s] ValidityTime interval:[%d]", UpfContext.NfId, UpfContext.NfStatusSubs)
			//interval
			UpfContext.SubscribeTimerId = TimerStart(UpfContext.NfStatusSubs, UpfContext.NfId, NfSubscriptionTimer)
		} else {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "SendNFStatusSubscribe NfInstanceId:[%s]  StatusCode:[%d]", UpfContext.NfId, res.StatusCode)
		}
	}
	return
}

// Unsubscribe UPF
func SendNFStatusUnSubscribe() (err error) {
	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendNFUnSubscribe SubscriptionId:%s", UpfContext.SubscriptionId)
	// Set client and set url
	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(UpfContext.NrfUri)
	configuration.AddDefaultHeader("authorization", "Bearer"+" "+UpfContext.OAuthToken)
	client := Nnrf_NFManagement.NewAPIClient(configuration)

	var res *http.Response
	res, err = client.SubscriptionIDDocumentApi.RemoveSubscription(context.Background(), UpfContext.SubscriptionId)
	if err != nil {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "UPF NFStatusUnSubscribe to NRF Error[%v]", err)
		return
	}
	if res != nil {
		if res.StatusCode < 300 {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "SendNFStatusSubscribe NfInstanceId:[%s] ValidityTime interval:[%d]", UpfContext.NfId, UpfContext.NfStatusSubs)
		} else {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "SendNFStatusSubscribe NfInstanceId:[%s]  StatusCode:[%d]", UpfContext.NfId, res.StatusCode)
		}
	}
	return
}
