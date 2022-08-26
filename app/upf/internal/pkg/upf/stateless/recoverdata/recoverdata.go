package recoverdata

import (
	"context"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"lite5gc/cmn/redisclt_v2"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types/configure"
	"strconv"
	"sync"
)

const moduleTag rlogger.ModuleTag = "stateless"
const (
	UPFPoolN4Session = "UPF_POOL_N4Session"
	UPFPoolN4Node    = "UPF_POOL_N4Node"
	UPFPoolNodeToGnb = "UPF_POOL_NodeToGnb"
	IsExistInRedis   = 1
	NotExistInRedis  = 0
	IsNullSyncMap    = 0
)

type UpfStatelessRSContext struct {
	Ctx1        context.Context
	Cancel1     context.CancelFunc
	ControlSUSP func()
	Wg          *sync.WaitGroup
	Ctx2        context.Context
	Cancel2     context.CancelFunc
}

var UpfCxt = &UpfStatelessRSContext{}

/*********************************************************************************/
//init N4node
func AddN4NodeToRedis(key string, ctxt interface{}) {
	rlogger.FuncEntry(moduleTag, nil)
	if configure.UpfConf.StatelessRestart {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		data, err := jsoniter.Marshal(ctxt)
		var UpfN4CxtTablekey = fmt.Sprintf("%s_%s", configure.UpfConf.N4.Local.Ipv4, key)
		if err == nil {
			redisclt_v2.Agent.HSet(ctx, UPFPoolN4Node, UpfN4CxtTablekey, data)
		}
	}
}
func DeleteN4NodeInRedis(key string, upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry(moduleTag, nil)
	if configure.UpfConf.StatelessRestart {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var UpfN4CxtTablekey = fmt.Sprintf("%s_%s", configure.UpfConf.N4.Local.Ipv4, key)
		redisclt_v2.Agent.HDel(ctx, UPFPoolN4Node, UpfN4CxtTablekey)
		upfCxt.Wg.Add(2)
		go DeleteNodeAboutRedisN4Session(key, upfCxt)
		go DeleteNodeAboutRedisPfcpGnb(key, upfCxt)
	}
}
func DeleteNodeAboutRedisN4Session(key string, upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry(moduleTag, nil)
	defer upfCxt.Wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolN4Session, cursor, "*"+key+"*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				redisclt_v2.Agent.HDel(ctx, UPFPoolN4Session, keys[i])
			}
			if cursor == 0 {
				return
			}
		}

	}
}
func DeleteNodeAboutRedisPfcpGnb(key string, upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry(moduleTag, nil)
	defer upfCxt.Wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolNodeToGnb, cursor, "*"+key+"*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				redisclt_v2.Agent.HDel(ctx, UPFPoolNodeToGnb, keys[i])
			}
			if cursor == 0 {
				return
			}
		}
	}
}
func ClearRedisAllN4Node(key string, upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry(moduleTag, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolN4Node, cursor, key+"*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				redisclt_v2.Agent.HDel(ctx, UPFPoolN4Node, keys[i])
			}
			if cursor == 0 {
				return
			}
		}

	}
}

/*********************************************************************************************/

/*********************************************************************************************/
//initN4context
func AddN4ContextToRedis(ctxt interface{}, smfIP string, seid uint64) {
	rlogger.FuncEntry(moduleTag, nil)
	if configure.UpfConf.StatelessRestart {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		data, err1 := jsoniter.Marshal(ctxt)
		var UpfN4CxtTablekey = fmt.Sprintf("%s_%s_%s",
			configure.UpfConf.N4.Local.Ipv4, smfIP, strconv.FormatUint(seid, 10))
		if err1 == nil {
			redisclt_v2.Agent.HSet(ctx, UPFPoolN4Session, UpfN4CxtTablekey, data)
		} else {
			rlogger.Trace(moduleTag, rlogger.ERROR, nil, "UPF MarshalJSON:%s", err1)
		}
	}
}
func DeleteN4ContextInRedis(smfIP string, seid uint64) {
	rlogger.FuncEntry(moduleTag, nil)
	if configure.UpfConf.StatelessRestart {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var UpfN4CxtTablekey = fmt.Sprintf("%s_%s_%s",
			configure.UpfConf.N4.Local.Ipv4, smfIP, strconv.FormatUint(seid, 10))
		redisclt_v2.Agent.HDel(ctx, UPFPoolN4Session, UpfN4CxtTablekey)
	}
}
func ClearRedisAllN4Session(key string, upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry(moduleTag, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolN4Session, cursor, key+"*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				redisclt_v2.Agent.HDel(ctx, UPFPoolN4Session, keys[i])
			}
			if cursor == 0 {
				return
			}
		}
	}
}

/******************************************************************************************/

/******************************************************************************************/
//init pfcp-gnb
func AddPfcpGnbToRedis(key string, ctxt interface{}) {
	if configure.UpfConf.StatelessRestart {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		data, err := jsoniter.Marshal(ctxt)
		var UpfN4CxtTablekey = fmt.Sprintf("%s_%s", configure.UpfConf.N4.Local.Ipv4, key)
		if err == nil {
			redisclt_v2.Agent.HSet(ctx, UPFPoolNodeToGnb, UpfN4CxtTablekey, data)
		}
	}
}
func DeletePfcpGnbInRedis(key string) {
	if configure.UpfConf.StatelessRestart {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var UpfN4CxtTablekey = fmt.Sprintf("%s_%s", configure.UpfConf.N4.Local.Ipv4, key)
		redisclt_v2.Agent.HDel(ctx, UPFPoolNodeToGnb, UpfN4CxtTablekey)
	}
}
func ClearRedisAllPfcpGnb(key string, upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry(moduleTag, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolNodeToGnb, cursor, key+"*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				redisclt_v2.Agent.HDel(ctx, UPFPoolNodeToGnb, keys[i])
			}
			if cursor == 0 {
				return
			}
		}
	}
}

/***************************************************************************************************/
