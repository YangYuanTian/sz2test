package main

import (
	_ "upf/app/job-template/internal/packed"

	"github.com/gogf/gf/v2/os/gctx"

	"upf/app/job-template/internal/cmd"
)

func main() {
	cmd.Main.Run(gctx.New())
}
