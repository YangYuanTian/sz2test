package nfctxt

import (
	"fmt"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/timermgr"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	"lite5gc/openapi/models"
	"math/rand"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NfTimerType int

const (
	NfHeartBeatTimer       NfTimerType = 1
	NfPeriodicTimer        NfTimerType = 2
	NfSubscriptionTimer    NfTimerType = 3
	NfMsgTimer             NfTimerType = 4
	NfProfilevalidityTimer NfTimerType = 5
	NfDeregTimer           NfTimerType = 6
)

func (p NfTimerType) String() string {
	var timeType string
	switch p {
	case NfHeartBeatTimer:
		timeType = fmt.Sprintf("NfHeartBeatTimer")
	case NfPeriodicTimer:
		timeType = fmt.Sprintf("NfPeriodicTimer")
	case NfSubscriptionTimer:
		timeType = fmt.Sprintf("NfSubscriptionTimer")
	case NfMsgTimer:
		timeType = fmt.Sprintf("NfMsgTimer")
	case NfDeregTimer:
		timeType = fmt.Sprintf("NfDeregTimer")
	case NfProfilevalidityTimer:
		timeType = fmt.Sprintf("NfProfilevalidityTimer")
	default:
		timeType = fmt.Sprintf("Unknown")
	}
	return timeType
}

type UPFContext struct {
	NfId            string
	NfType          models.NfType
	GroupId         string
	Scheme          string
	Addr            string
	Port            int
	profile         models.NfProfile //cache local NfProfile
	NrfUri          string
	NrfUriStatus    int32 //0--init  1--ok nf check nrf status
	NfService       map[models.ServiceName]models.NfService
	ServiceNameList []string
	timerMgr        *timermgr.TimerMgr
	HeartBeatSec    time.Duration
	TimerId         int64

	SubscriptionId   string
	NfStatusSubs     time.Duration //for nf status subscribe
	SubscribeTimerId int64         //timer for nf status subscribe

	//cache nf profile from nrf
	NfProfileResult        map[models.NfType][]models.NfProfile
	NfProfileResultSyncMap sync.Map

	ValidateTimerId int64 //NfProfileResult validate time
	// The NF instanceID is mapped to the smfContext
	NFIDOfSmfContext        map[string][]models.SmContextCreateData
	NFIDOfSmfContextSyncMap sync.Map

	// jwt token
	OAuthToken string
}

var UpfContext = &UPFContext{}

// free5gc/UPF/util
func InitUPFContext(UpfContext *UPFContext) {
	rlogger.FuncEntry(types.ModuleUpfSbi, nil)
	configuration := configure.UpfConf

	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "UPF Version[%s.%s] ", configuration.Version.Main, configuration.Version.Patch)
	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "UPF Log Level[%s] Path[%s] Topic[%s] Control[%d]",
		configuration.Logger.Level, configuration.Logger.Path, configuration.Logger.Topic, configuration.Logger.Control)

	//UpfContext.NfId = uuid.New().String()
	UpfContext.NfId = configure.UpfConf.Service.InstanceId
	UpfContext.NfType = models.NfType_UPF
	nrfClient := configuration.Sbi.Nrf

	sbi := configuration.Sbi.Upf

	UpfContext.NrfUri = fmt.Sprintf("%s://%s:%d", nrfClient.Scheme, nrfClient.Addr.Ip, nrfClient.Addr.Port)

	UpfContext.Scheme = sbi.Scheme
	UpfContext.Addr = configuration.N4.Local.Ipv4
	UpfContext.Port = sbi.Addr.Port
	//UpfContext.HeartBeatSec = 10
}

func (context *UPFContext) GetIPv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", context.Scheme, context.Addr, context.Port)
}

func (context *UPFContext) GetNfStatusNotify() string {
	url := "/notifications/nrf/nf-status/v1"
	return context.GetIPv4Uri() + url
}

func (context *UPFContext) InitNFService(serviceName []string, version string) {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	//for index, nameString := range serviceName {
	for _, nameString := range serviceName {
		name := models.ServiceName(nameString)
		context.NfService[name] = models.NfService{
			ServiceInstanceId: context.NfId,
			ServiceName:       name,
			Versions: &[]models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          (models.UriScheme)(context.Scheme),
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       context.GetIPv4Uri(),
			IpEndPoints: &[]models.IpEndPoint{
				{
					Ipv4Address: context.Addr,
					Transport:   models.TransportProtocol_TCP,
					Port:        int32(context.Port),
				},
			},
		}
	}
}

// consumer
func BuildNFInstance(ctx *UPFContext) (profile models.NfProfile, err error) {
	rlogger.FuncEntry(types.ModuleUpfSbi, nil)

	profile.NfInstanceId = ctx.NfId
	profile.NfStatus = models.NfStatus_REGISTERED
	profile.NfType = models.NfType_UPF
	//profile.HeartBeatTimer = 10

	if ctx.Addr == "" {
		err = fmt.Errorf("UPF Address is empty")
		return
	}

	var (
		SNssaiUpfInfoListTemp models.SnssaiUpfInfoItem

		DnnUpfInfoItemTemp     models.DnnUpfInfoItem
		SNssaiUpfInfoListSlice []models.SnssaiUpfInfoItem

		taiStr                    []string
		InterfaceUpfInfoItemTemp  models.InterfaceUpfInfoItem
		InterfaceUpfInfoItemSlice []models.InterfaceUpfInfoItem
	)

	SNssaiUpfInfoListTemp.SNssai = &models.Snssai{}

	UpfSel := configure.CmUpfConf.UpfSel

	for i, _ := range UpfSel {
		UpfSel[i].UpfIp = configure.CmUpfConf.N4.Local.Ipv4
	}

	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "configure.UpfConf.UpfSel: %v", UpfSel)
	for _, v := range UpfSel {
		// 按照逗号分割UPFSelection的Snssai配置项
		SnssaiSlice := strings.Split(v.Snssai, "-")
		if len(SnssaiSlice) > 0 {
			Sst, err := strconv.Atoi(SnssaiSlice[0])
			if err != nil {
				rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil,
					"UPF ->NRF BuildNFInstance fail... err: %v", err)
			}
			SNssaiUpfInfoListTemp.SNssai.Sst = int32(Sst)
			if len(SnssaiSlice) > 1 {
				SNssaiUpfInfoListTemp.SNssai.Sd = SnssaiSlice[1]
			}
		}
		// 按照逗号分割UPFSelection的DNN配置项
		DnnNames := strings.Split(v.DnnName, ",")
		for _, dnn := range DnnNames {
			if len(dnn) > 0 {
				DnnUpfInfoItemTemp.Dnn = dnn

				SNssaiUpfInfoListTemp.DnnUpfInfoList = append(SNssaiUpfInfoListTemp.DnnUpfInfoList, DnnUpfInfoItemTemp)
			}
		}
		SNssaiUpfInfoListSlice = append(SNssaiUpfInfoListSlice, SNssaiUpfInfoListTemp)
		SNssaiUpfInfoListTemp = models.SnssaiUpfInfoItem{SNssai: &models.Snssai{}}
		// 按照逗号分割UPFSelection的Tai配置项
		Tais := strings.Split(v.Tai, ",")
		for _, tai := range Tais {
			if len(tai) > 0 {
				taiStr = append(taiStr, tai)
			}
		}
	}
	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, "SNssaiUpfInfoListTemp%+v", SNssaiUpfInfoListTemp)

	upfSbiStr := fmt.Sprintf("%s:%d", configure.UpfConf.N4.Local.Ipv4, configure.UpfConf.N4.Local.Port)
	InterfaceUpfInfoItemTemp.Ipv4EndpointAddresses = []string{upfSbiStr}

	InterfaceUpfInfoItemSlice = append(InterfaceUpfInfoItemSlice, InterfaceUpfInfoItemTemp)

	profile.UpfInfo = &models.UpfInfo{
		SNssaiUpfInfoList:    SNssaiUpfInfoListSlice,
		SmfServingArea:       taiStr,
		InterfaceUpfInfoList: InterfaceUpfInfoItemSlice,
		PduSessionTypes:      nil,
	}

	profile.Ipv4Addresses = append(profile.Ipv4Addresses, ctx.Addr)

	defaultNotificationSubscription := models.DefaultNotificationSubscription{
		CallbackUri:      fmt.Sprintf("%s/nupf-callback/v1/n1-message-notify", ctx.GetIPv4Uri()),
		NotificationType: models.NotificationType_N1_MESSAGES,
		N1MessageClass:   models.N1MessageClass__5_GMM,
	}
	profile.DefaultNotificationSubscriptions = append(profile.DefaultNotificationSubscriptions,
		defaultNotificationSubscription)
	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "UPF ->NRF BuildNFInstance detail:(%+v)", profile)
	return
}

func NrfClientStart(appContext *types.AppContext) {
	rlogger.FuncEntry(types.ModuleUpfSbi, nil)
	defer func() {
		if err := recover(); err != nil {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "NrfClientStart failed with %v", err)
			debug.PrintStack()
		}
	}()

	InitUPFContext(UpfContext)

	//UPF SBI NrfUri SAVE
	appContext.AddRestartNrf(UpfContext.NrfUri)

	UpfContext.timerMgr = timermgr.NewTimerMgr(appContext.Ctx, 1, 200)

	profile, err := BuildNFInstance(UpfContext)
	if err != nil {
		rlogger.Trace(types.ModuleUpfSbi, rlogger.ERROR, nil, "UPF ->NRF BuildNFInstance fail... err: %v", err)
		return
	} else {
		//cache type NfTimerType int
		UpfContext.profile = profile //profile models.NfProfile
		_, _, err = SendRegisterNFInstance(UpfContext.NrfUri, UpfContext.NfId, profile)
		if err != nil {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF ->NRF NrfClientStart fail...", err.Error())
		} else {
			err = SendNFStatusSubscribe()
			if err != nil {
				rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF ->NRF NFStatusSubscribe fail...", err.Error())
			}
			//discord nf server
			rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "NrfClientStart register to NRF success ...")
			return
		}
	}
	rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "NrfClientStart register to NRF fail ...")
}

func NrfClientStop() {
	defer func() {
		err := SendDeregisterNFInstance()
		if err != nil {
			AppContext.TimesCountResNrf(UpfContext.NrfUri)
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF send Deregister msg to nrf server failed...")
		}
		err = SendNFStatusUnSubscribe()
		if err != nil {
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF send UnSubscribe msg to nrf server failed...")
		}
	}()

	//UpfContext.timerMgr.Destroy()
	rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, "stop sbi client with nrf", UpfContext.NrfUri)
}

var AppContext *types.AppContext

func NRFRestart() {
	go func() {
		NrfClientStop()
		NrfClientStart(AppContext)
	}()
}

// timeout callback function
func timerOutCallback(params interface{}) {
	args := reflect.ValueOf(params) //interface to value, which is a slice

	lens := args.Len()
	if lens == 2 {
		NfInstanceId := reflect.ValueOf(args.Index(0).Interface()).String()
		TimerType := (NfTimerType)(reflect.ValueOf(args.Index(1).Interface()).Int())
		rlogger.Trace(types.ModuleUpfSbi, rlogger.TRACE, nil, "timer out_callback  NfInstanceId:%s ", NfInstanceId)

		switch TimerType {
		case NfHeartBeatTimer:
			//patch
			err := SendUpdateNFInstance(UpfContext.NrfUri, UpfContext.NfId)
			if err == nil {
				rlogger.Trace(types.ModuleUpfSbi, rlogger.TRACE, nil, "UPF--->NRF UpdateNFInstance success")
				UpfContext.TimerId = TimerStart((time.Duration)(UpfContext.HeartBeatSec), UpfContext.NfId, NfHeartBeatTimer)
			} else {
				rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "SendUpdateNFInstance NfInstanceId:%s fail,retry to register to nrf", NfInstanceId)
				//retry to register to nrf
				//1.stop all nf timer subscribe ?
				//2.re-RegisterNFInstance
				var newNrfUri string

				newNrfUri, _, err = SendRegisterNFInstance(UpfContext.NrfUri, UpfContext.NfId, UpfContext.profile)
				if err != nil {
					rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF ->NRF NrfClientStart fail...", err.Error())
				} else {
					rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "UPF ->NRF update NrfUri:%s(not update now)", newNrfUri)

					err = SendNFStatusSubscribe()
					if err != nil {
						rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF ->NRF NFStatusSubscribe fail...", err.Error())
					}
				}
			}

		case NfSubscriptionTimer:
			rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "NfInstanceId:%s SubscriptionId:%s %s  ", NfInstanceId, UpfContext.SubscriptionId, TimerType.String())
			//Once the subscription expires, if the NF Service Consumer wants to keep receiving status notifications, it shall create a new subscription in the NRF.
			err := SendNFStatusSubscribe()
			if err != nil {
				rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "NfInstanceId:%s creat new Subscription fail", NfInstanceId)
			}
		case NfMsgTimer:
			//TBD
			rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "NfInstanceId:%s %s timeout", NfInstanceId, TimerType.String())

		case NfPeriodicTimer:
			//TBD
			rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "NfInstanceId:%s %s timeout", NfInstanceId, TimerType.String())
		case NfDeregTimer:
			rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "NfInstanceId:%s %s timeout", NfInstanceId, TimerType.String())
			TimerStop(UpfContext.TimerId)

			err := SendDeregisterNFInstance()
			if err != nil {
				fmt.Println("loop SendDeregisterNFInstance fail")
			}

			profile, err := BuildNFInstance(UpfContext)
			if err != nil {
				rlogger.Trace(types.ModuleUpfSbi, rlogger.INFO, nil, "UPF ->NRF BuildNFInstance fail...")
			} else {
				_, _, err = SendRegisterNFInstance(UpfContext.NrfUri, UpfContext.NfId, profile)
				if err != nil {
					rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "UPF ->NRF NrfClientStart fail...", err.Error())
				} else {
					rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "UPF ->NRF SendRegisterNFInstance success")
				}
			}
			rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "NrfClientStart register to NRF success ...")
		case NfProfilevalidityTimer:
			rlogger.Trace(types.ModuleUpfSbi, rlogger.DEBUG, nil, "NfInstanceId:%s %s Discover NF from NRF", NfInstanceId, TimerType.String())
		default:
			rlogger.Trace(types.ModuleUpfSbi, rlogger.WARN, nil, "timeout_callback  NfInstanceId:%s  TimerType:%s timeout", NfInstanceId, TimerType.String())
		}
	}
}

func TimerStart(sec time.Duration, NfInstanceId string, TimerType NfTimerType) int64 {
	timeOutCB := timermgr.NewOnTimeOut(timerOutCallback, NfInstanceId, TimerType)
	rand.Seed(time.Now().UnixNano())
	//timerMgr.AddPeriodTimer(5, timeOutCB)
	return UpfContext.timerMgr.AddAfterTimer(sec, timeOutCB) //make timer+1 for hb
}

func TimerStop(timerID int64) {
	UpfContext.timerMgr.CancelTimer(timerID)
}
