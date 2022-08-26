package n4context

import (
	"fmt"
	"lite5gc/cmn/rlogger"
	"lite5gc/cmn/syncmap"
	"lite5gc/upf/stateless/recoverdata"
)

var seidUpfN4CxtTable syncmap.SyncMap //key:seid,value:*N4Cxt
func GetN4Table() *syncmap.SyncMap {
	return &seidUpfN4CxtTable
}
func CreateN4Context(key interface{}) error {
	rlogger.FuncEntry(moduleTag, nil)
	var err error
	switch key.(type) {
	case N4SessionIDKey:
		n4Ctxt := &N4SessionContext{}
		err = seidUpfN4CxtTable.Set(key, n4Ctxt) // seidUpfN4CxtTable 隐含取地址调用方法
		if err != nil {
			err = fmt.Errorf("failed to create the seidUpfN4CxtTable, error(%s)", err)
		}
	default:
		err = fmt.Errorf("invalid key")
	}

	return err
}

func AddIndexN4Context(key interface{}, ctxt *N4SessionContext) error {
	rlogger.FuncEntry(moduleTag, nil)

	var err error
	switch key.(type) {
	case N4SessionIDKey:
		err = seidUpfN4CxtTable.Set(key, ctxt)
		if err != nil {
			if err.Error() == "key exist" {
				seidUpfN4CxtTable.Update(key, ctxt)
				err = nil
			} else {
				err = fmt.Errorf("failed to set key(%d),err(%s)", key.(N4SessionIDKey), err)
			}
		}
		recoverdata.AddN4ContextToRedis(ctxt, ctxt.SmfSEID.IPv4Addr.String(), uint64(key.(N4SessionIDKey)))
	default:
		err = fmt.Errorf("invalid key type")
	}
	return err
}
func AddN4ContextFromRedis(key interface{}, ctxt *N4SessionContext) error {
	rlogger.FuncEntry(moduleTag, nil)
	var err error
	switch key.(type) {
	case N4SessionIDKey:
		err = seidUpfN4CxtTable.Set(key, ctxt)
		if err != nil {
			if err.Error() == "key exist" {
				seidUpfN4CxtTable.Update(key, ctxt)
				err = nil
			} else {
				err = fmt.Errorf("failed to set key(%d),err(%s)", key.(N4SessionIDKey), err)
			}
		}
	default:
		err = fmt.Errorf("invalid key type")
	}
	return err
}
func GetN4Context(key interface{}) (n4Ctxt *N4SessionContext, err error) {
	rlogger.FuncEntry(moduleTag, nil)

	switch key.(type) {
	case N4SessionIDKey:
		val := seidUpfN4CxtTable.Get(key)
		if val == nil {
			err = fmt.Errorf("failed to find N4SessionContext with SEID key(%d)", key.(N4SessionIDKey))
			return
		}
		ctxt, ok := val.(*N4SessionContext)
		if !ok {
			err = fmt.Errorf("invalid n4 session context type")
			return
		}
		n4Ctxt = ctxt

	default:
		err = fmt.Errorf("invalid key")
	}
	return
}

func UpdateN4Context(key interface{}, n4Ctxt *N4SessionContext) error {
	rlogger.FuncEntry(moduleTag, n4Ctxt)

	if n4Ctxt == nil {
		return fmt.Errorf("invalid input parameter, nil n4Ctxt")
	}
	switch key.(type) {
	case N4SessionIDKey:
		seidUpfN4CxtTable.Update(key, n4Ctxt)
		recoverdata.AddN4ContextToRedis(n4Ctxt, n4Ctxt.SmfSEID.IPv4Addr.String(), uint64(key.(N4SessionIDKey)))
	default:
		return fmt.Errorf("invalid key")
	}

	return nil
}

func DeleteN4Context(key interface{}, n4Ctxt *N4SessionContext) error {
	rlogger.FuncEntry(moduleTag, nil)
	switch key.(type) {
	case N4SessionIDKey:
		seidUpfN4CxtTable.Del(key)
		recoverdata.DeleteN4ContextInRedis(n4Ctxt.SmfSEID.IPv4Addr.String(), uint64(key.(N4SessionIDKey)))
	default:
		return fmt.Errorf("invalid key")
	}

	return nil
}

func LengthOfN4ContextTbl(key KeyType) uint64 {
	var length uint64
	switch key {
	case N4SessionIDCxtType:
		length = seidUpfN4CxtTable.Length64()
	default:
		length = 0 //invalid
	}

	return length
}
func ValuesOfN4ContextTbl(key KeyType) (CxtList []*N4SessionContext, err error) {
	switch key {
	case N4SessionIDCxtType:
		seidUpfN4CxtTable.Range(func(key, value interface{}) bool {
			//fmt.Println(key, value)
			ctxt, ok := value.(*N4SessionContext)
			if !ok {
				err = fmt.Errorf("invalid n4 session context type")
				return false
			}
			CxtList = append(CxtList, ctxt)
			return true
		})
	default:
		err = fmt.Errorf("invalid key")
		return
	}
	return
}
