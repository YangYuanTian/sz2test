package main

import (
	_ "upf/app/svc-template/internal/packed"

	"github.com/gogf/gf/v2/os/gctx"

	"upf/app/svc-template/internal/cmd"
)

func main() {
	cmd.Main.Run(gctx.New())
}
