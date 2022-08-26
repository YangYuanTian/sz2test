package nfctxt

import (
	"context"
	"fmt"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/openapi/Nnrf_NFDiscovery"
	"lite5gc/openapi/models"
	"net/http"
	"time"
)

func SendNFDiscover(nrfUri string, targetNfType models.NfType, requestNfType models.NfType, param Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (result models.SearchResult, err error) {

	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)

	var res *http.Response

	//5.3.2.2	NFDiscover
	//This service operation discovers the set of NF Instances (and their associated NF Service Instances), represented by their NF Profile,
	//that are currently registered in NRF and satisfy a number of input query parameters.
	//Before a service consumer invokes this service operation, it shall consider if it is possible to reuse the results from a previous searching (service discovery).
	//The service consumer should reuse the previous result if input query parameters in the new service discovery request
	//are the same as used for the previous search and the validity period of the result is not expired.
	//The service consumer may consider reusing the previous result if the attributes as required for the new query is also part of NF profile of the candidates NFs from a previous query.
	//In such case, when the results of a previous query are reused, the service consumer need consider that the results, e.g. in terms of the number of discovered NFs,
	//can be different than the potential results obtained after performing a new query.

	//udm don't care nf SearchNFInstancesParamOpts

	result, res, err = client.NFInstancesStoreApi.SearchNFInstances(context.Background(), targetNfType, requestNfType, &param)
	if err != nil || res == nil {
		rlogger.Trace(types.ModuleSmfSbi, rlogger.ERROR, nil, "UDM SendNFDiscover to NRF Error[%v]", err.Error())
		return
	} else {
		switch res.StatusCode {
		case 200:
			//On success, "200 OK" shall be returned.
			//The response body shall contain a validity period, during which the search result can be cached by the NF Service Consumer, and an array of NF Profile objects,
			//that satisfy the search filter criteria (e.g., all NF Instances offering a certain NF Service name).
			return result, nil
		case 400:
			err = fmt.Errorf("400 Bad Request")
			return result, err
		case 500:
			err = fmt.Errorf("500 Internal Server Error")
			return result, err
		default:
			err = fmt.Errorf("res.StatusCode %d", res.StatusCode)
			return result, err
		}
	}
}

func NFInstancesDiscover(targetNfType models.NfType) (err error) {
	requestNfType := UpfContext.NfType //models.NfType_UDM
	localVarOptionals := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		// 	DataSet: optional.NewInterface(models.DataSetId_SUBSCRIPTION),
	}

	rlogger.Trace(types.ModuleSmfSbi, rlogger.INFO, nil, "[%s] Discover targetNfType:[%s]", requestNfType, targetNfType)

	result, err := SendNFDiscover(UpfContext.NrfUri, targetNfType, requestNfType, localVarOptionals)
	if err != nil {
		rlogger.Trace(types.ModuleSmfSbi, rlogger.WARN, nil, "[%s] Discover Error:%s", requestNfType, err.Error())
		return
	}
	var NfProfiles []models.NfProfile
	//find first
	for _, nfProfile := range result.NfInstances {
		NfProfiles = append(NfProfiles, nfProfile)
	}

	//cache result.NfInstances &start timer with validity period
	//if UpfContext.NfProfileResult == nil {
	//	UpfContext.NfProfileResult = make(map[models.NfType][]models.NfProfile)
	//}

	UpfContext.NfProfileResultSyncMap.Store(targetNfType, NfProfiles)
	//UpfContext.NfProfileResult[targetNfType] = NfProfiles

	UpfContext.ValidateTimerId = TimerStart(time.Duration(result.ValidityPeriod), UpfContext.NfId, NfProfilevalidityTimer)
	return
}

//func GetUPFPreviousIPFromNRF(appContext *types.AppContext)(upfIP string){
//	InitUPFContext(UpfContext)
//	UpfContext.timerMgr = timermgr.NewTimerMgr(appContext.Ctx, 1, 500)
//	err := NFInstancesDiscover(models.NfType_UPF)
//	if err != nil {
//		rlogger.Trace(types.ModuleSmfSM, rlogger.ERROR, nil, "UPF fails to select UPF based on NRF, error(%v)", err)
//	} else {
//		if v, ok := UpfContext.NfProfileResultSyncMap.Load(models.NfType_UPF); ok {
//			upfProfileSlice := v.([]models.NfProfile)
//			for _, upfProfile := range upfProfileSlice {
//				if upfProfile.NfInstanceId=="uuid_UPF_0001"{
//					value:=upfProfile.UpfInfo.InterfaceUpfInfoList[0].Ipv4EndpointAddresses[0]
//					str:=strings.Split(value,":")
//					upfIP=str[0]
//					break
//				}
//			}
//		}
//	}
//	return
//}

//func GetUPFPreviousIPFromNRF(appContext *types.AppContext)(upfIP string){
//	InitUPFContext(UpfContext)
//	UpfContext.timerMgr = timermgr.NewTimerMgr(appContext.Ctx, 1, 500)
//	err := NFInstancesDiscover(models.NfType_UPF)
//	if err != nil {
//		rlogger.Trace(types.ModuleSmfSM, rlogger.ERROR, nil, "UPF fails to select UPF based on NRF, error(%v)", err)
//	} else {
//		if v, ok := UpfContext.NfProfileResultSyncMap.Load(models.NfType_UPF); ok {
//			upfProfileSlice := v.([]models.NfProfile)
//			for _, upfProfile := range upfProfileSlice {
//				if upfProfile.NfInstanceId=="uuid_UPF_0001"{
//					value:=upfProfile.UpfInfo.InterfaceUpfInfoList[0].Ipv4EndpointAddresses[0]
//					str:=strings.Split(value,":")
//					upfIP=str[0]
//					break
//				}
//			}
//		}
//	}
//	return
//}
