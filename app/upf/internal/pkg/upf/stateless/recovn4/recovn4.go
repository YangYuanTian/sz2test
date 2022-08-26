package recovn4

import (
	"context"
	jsoniter "github.com/json-iterator/go"
	"lite5gc/cmn/redisclt_v2"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/types"
	"lite5gc/cmn/types/configure"
	utils2 "lite5gc/cmn/utils"
	"lite5gc/upf/context/n4context"
	"lite5gc/upf/context/pfcpgnbcontext"
	"lite5gc/upf/cp/n4node"
	"lite5gc/upf/cp/n4node/typedef"
	"lite5gc/upf/cp/n4udp"
	"lite5gc/upf/cp/pdr"
	"lite5gc/upf/metrics"
	. "lite5gc/upf/stateless/recoverdata"
	"strconv"
	"strings"
)

func InitUpfNodePool(upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry("moduleTag", nil)
	defer upfCxt.Wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := redisclt_v2.Agent.Exists(ctx, UPFPoolN4Node)
	l := typedef.LengthOfNodeTbl("")
	if cmd.Val() == NotExistInRedis || l != IsNullSyncMap {
		//upfCxt.Cancel2()
		rlogger.Trace("moduleTag", rlogger.INFO, nil, "redis not have UPF N4 Node context")
		return
	}
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolN4Node, cursor, configure.UpfConf.N4.Local.Ipv4+"_*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				var n = &typedef.Node{}
				byte, err := redisclt_v2.Agent.HGet(ctx, UPFPoolN4Node, keys[i]).Bytes()
				if err != nil {
					continue
				}
				jsoniter.Unmarshal(byte, &n)
				s := strings.Split(keys[i], "_")
				typedef.AddNodeFromRedis(s[1], n)
				n.Server.UdpConn = n4udp.Server.UdpConn
				nfsm, err := n4node.NewNodeFSM()
				if err != nil {
					rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Failed to create nodeProcFSM, err:%s", err)
				}
				nfsmHB, err := n4node.NewNodeProcFSM()
				if err != nil {
					rlogger.Trace(types.ModuleUpfN4Node, rlogger.ERROR, nil, "Failed to create nodeProcFSM, err:%s", err)
				}
				n.NFsm = &typedef.NodeFSMs{NodeFsm: nfsm, NodeHBFSM: nfsmHB}
				go n4node.HeartbeatSetup(n)
			}
			if cursor == 0 {
				return
			}
			rlogger.Trace("moduleTag", rlogger.DEBUG, nil, "UPF successfully pull n4node context from redis")
		}
	}
}
func InitSeidUpfN4CxtTable(upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry("moduleTag", nil)
	defer upfCxt.Wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upfCxt.Ctx2 = ctx
	upfCxt.Cancel2 = cancel
	cmd := redisclt_v2.Agent.Exists(ctx, UPFPoolN4Session)
	cmd1 := redisclt_v2.Agent.Exists(ctx, UPFPoolN4Node)
	l := n4context.LengthOfN4ContextTbl(n4context.N4SessionIDCxtType)
	if cmd.Val() == NotExistInRedis || l != IsNullSyncMap {
		rlogger.Trace("moduleTag", rlogger.DEBUG, nil, "redis not have UPF N4Session")
		return
	}
	if cmd.Val() == IsExistInRedis && cmd1.Val() == NotExistInRedis {
		rlogger.Trace("moduleTag", rlogger.DEBUG, nil, "redis not have UPF N4 Node but have N4Session,doing clean n4session in redis")
		ClearRedisAllN4Session(configure.UpfConf.N4.Local.Ipv4, upfCxt)
		return
	}
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		case <-upfCxt.Ctx2.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolN4Session, cursor, configure.UpfConf.N4.Local.Ipv4+"_*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				byte, err := redisclt_v2.Agent.HGet(ctx, UPFPoolN4Session, keys[i]).Bytes()
				if err != nil {
					continue
				}
				s := strings.Split(keys[i], "_")
				seid, _ := strconv.Atoi(s[2])
				ctxt := &n4context.N4SessionContext{}
				jsoniter.Unmarshal(byte, ctxt)
				ctxt.MetricItems, _ = metrics.SessionCounterInit()
				ctxt.MetricItemsSnapshot, _ = metrics.SessionCounterInit()
				n4context.AddN4ContextFromRedis(n4context.N4SessionIDKey(seid), ctxt)
				err = pdr.ConfigPDRsTable(ctxt)
				if err != nil {
					rlogger.Trace("moduleTag", rlogger.ERROR, utils2.Seid(ctxt.SEID), "Config PDRs table failed:%s", err)
				}
			}
			if cursor == 0 {
				return
			}
			rlogger.Trace("moduleTag", rlogger.DEBUG, nil, "UPF successfully pull N4Session from redis")
		}
	}
}
func InitPfcpGnbTable(upfCxt *UpfStatelessRSContext) {
	rlogger.FuncEntry(types.ModuleUpfN4Context, nil)
	defer upfCxt.Wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upfCxt.Ctx2 = ctx
	upfCxt.Cancel2 = cancel
	cmd := redisclt_v2.Agent.Exists(ctx, UPFPoolNodeToGnb)
	cmd1 := redisclt_v2.Agent.Exists(ctx, UPFPoolN4Node)
	l := pfcpgnbcontext.LengthOfTbl("")
	if cmd.Val() == NotExistInRedis || l != IsNullSyncMap {
		rlogger.Trace(types.ModuleUpfN4Context, rlogger.DEBUG, nil, "redis not have UPF PfcpGnb context")
		return
	}
	if cmd.Val() == IsExistInRedis && cmd1.Val() == NotExistInRedis {
		rlogger.Trace(types.ModuleUpfN4Context, rlogger.DEBUG, nil, "redis not have UPF N4 Node but have PfcpGnb context,doing clean PfcpGnb context in redis")
		ClearRedisAllPfcpGnb(configure.UpfConf.N4.Local.Ipv4, upfCxt)
		return
	}
	var cursor uint64
	var err error
	for {
		select {
		case <-upfCxt.Ctx1.Done():
			return
		case <-upfCxt.Ctx2.Done():
			return
		default:
			var keys []string
			keys, cursor, err = redisclt_v2.Agent.HScan(ctx, UPFPoolNodeToGnb, cursor, configure.UpfConf.N4.Local.Ipv4+"_*", 20).Result()
			if err != nil {
				return
			}
			for i := 0; i < len(keys); i = i + 2 {
				byte, err := redisclt_v2.Agent.HGet(ctx, UPFPoolNodeToGnb, keys[i]).Bytes()
				if err != nil {
					continue
				}
				var pfcpGnbinfo = &pfcpgnbcontext.PfcpGnbInfo{}
				jsoniter.Unmarshal(byte, pfcpGnbinfo)
				s := strings.Split(keys[i], "_")
				pfcpgnbcontext.AddPfcpGnbFromRedis(s[1], pfcpGnbinfo)
			}
			if cursor == 0 {
				return
			}
			rlogger.Trace(types.ModuleUpfN4Context, rlogger.DEBUG, nil, "UPF successfully pull PfcpGnb context from redis")
		}
	}
}
func InitUPFAllTables(appContext *types.AppContext) {
	rlogger.FuncEntry("moduleTag", nil)
	UpfCxt.Wg = appContext.Wg
	UpfCxt.Cancel1 = appContext.Cancel
	UpfCxt.Ctx1 = appContext.Ctx
	UpfCxt.Wg.Add(3)
	go InitSeidUpfN4CxtTable(UpfCxt)
	go InitPfcpGnbTable(UpfCxt)
	go InitUpfNodePool(UpfCxt)
}
