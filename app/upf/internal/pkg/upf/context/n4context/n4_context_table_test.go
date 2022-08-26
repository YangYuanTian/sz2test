package n4context_test

import (
	"fmt"
	"lite5gc/cmn/message/pfcp"
	. "lite5gc/upf/context/n4context"
	"testing"
)

func TestAddIndexN4Context(t *testing.T) {

	key, _ := GetSEID()

	cxt := &N4SessionContext{SEID: key,
		PDRs: []*pfcp.IECreatePDR{&pfcp.IECreatePDR{}, &pfcp.IECreatePDR{}},
	}
	err := AddIndexN4Context(N4SessionIDKey(key), cxt)

	key, _ = GetSEID()
	cxt = &N4SessionContext{SEID: key,
		PDRs: []*pfcp.IECreatePDR{&pfcp.IECreatePDR{}, &pfcp.IECreatePDR{}},
	}
	cxt.SEID = key

	err = AddIndexN4Context(N4SessionIDKey(key), cxt)

	key, _ = GetSEID()
	cxt = &N4SessionContext{SEID: key,
		PDRs: []*pfcp.IECreatePDR{&pfcp.IECreatePDR{}, &pfcp.IECreatePDR{}},
	}
	cxt.SEID = key
	cxt.PDRs[0].Set()
	cxt.PDRs[0].PDI.QFIs = []*pfcp.IEQFI{&pfcp.IEQFI{}} // 可选IE，QFI是一个空指针，使用时需要赋值
	cxt.PDRs[0].PDI.QFIs[0].Set(10)
	err = AddIndexN4Context(N4SessionIDKey(1), cxt)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Add N4 Context failed.key:%v", key)
	}

	length := LengthOfN4ContextTbl(N4SessionIDCxtType)
	fmt.Println("The number of records in the n4 context table is ", length)

	/*cxtResult, err := GetN4Context(N4SessionIDKey(key))
	if err != nil {
		t.Errorf("Get N4 Context failed.key:%v", key)
	}*/

	//fmt.Printf("Record in the n4 context table: %#v\n", cxtResult)

	n4list, err := ValuesOfN4ContextTbl(N4SessionIDCxtType)
	if err != nil {
		fmt.Println(err)
	} else {
		for i, value := range n4list {
			fmt.Println(i, value)
		}
	}

}
