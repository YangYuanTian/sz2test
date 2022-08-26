package typedef

import (
	"fmt"
	"upf/internal/pkg/cmn/syncmap"
	"upf/internal/pkg/upf/stateless/recoverdata"
)

var upfNodePool syncmap.SyncMap // map[string]*Node key:IP.String()

func ValuesOfNodeTbl() (CxtList []*Node, err error) {

	upfNodePool.Range(func(key, value interface{}) bool {
		//fmt.Println(key, value)
		ctxt, ok := value.(*Node)
		if !ok {
			err = fmt.Errorf("invalid node type")
			return false
		}
		CxtList = append(CxtList, ctxt)
		return true
	})

	return
}

func AddNode(key string, ctxt *Node) error {

	var err error

	err = upfNodePool.Set(key, ctxt)
	if err != nil {
		err = fmt.Errorf("failed to set key(%s),err(%s)", key, err)
	}
	recoverdata.AddN4NodeToRedis(key, ctxt)
	return nil
}
func AddNodeFromRedis(key string, ctxt *Node) error {
	var err error

	err = upfNodePool.Set(key, ctxt)
	if err != nil {
		err = fmt.Errorf("failed to set key(%s),err(%s)", key, err)
	}
	return nil
}
func GetNode(key string) (n *Node, err error) {

	val := upfNodePool.Get(key)
	if val == nil {
		err = fmt.Errorf("failed to find Node with peerIp key(%s)", key)
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	ctxt, ok := val.(*Node)
	if !ok {
		err = fmt.Errorf("invalid node type")
		//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
		return
	}
	n = ctxt
	//rlogger.Trace(types.SmfN4Layer, rlogger.ERROR, nil, err)
	return
}

func UpdateNode(key string, n *Node) error {

	if n == nil {
		return fmt.Errorf("invalid input parameter, nil Node")
	}

	upfNodePool.Update(key, n)

	return nil
}

func DeleteNode(key string) error {

	upfNodePool.Del(key)
	recoverdata.DeleteN4NodeInRedis(key, recoverdata.UpfCxt)
	return nil
}

func LengthOfNodeTbl(key string) uint64 {
	var length uint64
	length = upfNodePool.Length64()

	return length
}
