package n4layer

import (
	"fmt"
	"testing"
)

func TestUserForTest(t *testing.T) {
	t.Log("UserTest")
	usr := TestUser{}
	usr.Create()
	fmt.Println(usr)
}
