package main

import (
	_ "upf/app/api-template/internal/packed"

	"github.com/gogf/gf/v2/os/gctx"

	"upf/app/api-template/internal/cmd"
)

func main() {
	cmd.Main.Run(gctx.New())
}
