package main

// 探针：二进制附件字节直接喂生产 Presolve，验证 flag_scan 是否命中。
// 用法: go run ./cmd/presolve-binprobe --file <binary-path>

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

func main() {
	file := flag.String("file", "", "二进制附件路径")
	category := flag.String("category", "reverse", "题型")
	flag.Parse()

	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(2)
	}
	p := ctfplatform.NewPresolver(zap.NewNop())
	ch := &ctfplatform.Challenge{
		ID:          "binprobe",
		Title:       "probe",
		Description: "附件是一个 UPX 加壳的 ELF 可执行文件。分析二进制，找出 flag。",
		Category:    *category,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res := p.Presolve(ctx, ch, map[string]string{"attachment": string(data)})
	fmt.Printf("solved=%v engine=%q flags=%v detail=%q\n",
		res.Solved, res.Engine, res.Flags, res.Detail)
}
