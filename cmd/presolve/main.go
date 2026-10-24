// presolve-cli：把一段题干/附件文本喂给生产 presolve 引擎，打印候选 flag。
//
// 为什么存在：赛时手上有题干文本时，不该为了跑一次 presolve 去起整个服务。
// 该命令直接调用生产同一条链路（internal/ctfplatform.Presolver），
// 因此"这里没解出来"≈"服务里也解不出来"，判读不会偏差。
//
// 用法：
//   go run ./cmd/presolve --text-file q.txt
//   echo '密文 ...' | go run ./cmd/presolve
//   go run ./cmd/presolve --text-file q.txt --category crypto --json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	"secautomind-ai/internal/ctfplatform"
)

func main() {
	textFile := flag.String("text-file", "", "题干文本文件；留空则从 stdin 读")
	category := flag.String("category", "misc", "题型：misc/crypto/web/reverse/pwn（影响部分求解器分支）")
	id := flag.String("id", "local", "题目 ID（仅用于日志）")
	asJSON := flag.Bool("json", false, "输出 JSON")
	timeout := flag.Duration("timeout", 60*time.Second, "求解超时")
	flag.Parse()

	var raw []byte
	var err error
	if *textFile != "" {
		raw, err = os.ReadFile(*textFile)
	} else {
		raw, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取题干失败: %v\n", err)
		os.Exit(2)
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		fmt.Fprintln(os.Stderr, "题干为空：用 --text-file 或 stdin 传入")
		os.Exit(2)
	}

	presolver := ctfplatform.NewPresolver(zap.NewNop())
	ch := &ctfplatform.Challenge{ID: *id, Category: *category, Description: text}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	start := time.Now()
	res := presolver.Presolve(ctx, ch, nil)
	elapsed := time.Since(start)

	if *asJSON {
		out := map[string]any{
			"solved":  res.Solved,
			"flags":   res.Flags,
			"elapsed": elapsed.Round(time.Millisecond).String(),
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Printf("耗时: %s\n", elapsed.Round(time.Millisecond))
	if !res.Solved || len(res.Flags) == 0 {
		fmt.Println("结果: 未解出（solves=[]）")
		return
	}
	fmt.Printf("结果: 命中 %d 个候选\n", len(res.Flags))
	for i, f := range res.Flags {
		fmt.Printf("  [%d] %s\n", i+1, f)
	}
}
