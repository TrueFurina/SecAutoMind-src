// liverange：常驻真实靶场服务（live target range）。
//
// 为什么存在：internal/ctfplatform 的真靶机原先只能在 go test 里用 httptest 临时起，
// 测试结束靶机即消失 —— Agent 无法对"真实服务器"解题，只能对着题面文本空转
// （实测后果：反注水门禁 missing_execution_evidence，因为没有任何真实工具执行）。
// 本命令把**同一批真漏洞 handler**挂到固定端口常驻，使链路成立：
//
//	靶场分配地址 → 题面注入地址 → Agent 真发 HTTP 请求 → 从靶机响应里取 flag → /verify 判分
//
// 防作弊边界（重要）：
//   - GET /targets 只返回题面 + 地址，**不含 flag** —— 与真实赛题同构，静态读题面拿不到答案
//   - POST /verify 只回 {"correct": bool}，不回正确答案，杜绝"问靶场要答案"
//
// 用法：
//
//	go run ./cmd/liverange                    # 靶机 19001..，清单/判分 19000
//	curl http://127.0.0.1:19000/targets       # 取题面清单
//	curl -X POST http://127.0.0.1:19000/verify -d '{"id":"2001","flag":"flag{...}"}'
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"secautomind-ai/internal/ctfplatform"
)

// targetInfo 是**发给解题方**的题目信息：刻意不含 flag。
type targetInfo struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
	URL   string `json:"url"`
}

func main() {
	host := flag.String("host", "127.0.0.1", "监听地址")
	base := flag.Int("base-port", 19001, "首个靶机端口；第 i 道题占 base-port+i")
	admin := flag.Int("admin-port", 19000, "题目清单 / 判分端口")
	flag.Parse()

	specs := ctfplatform.NewLiveTargetSpecs()
	if len(specs) == 0 {
		log.Fatal("靶机清单为空：NewLiveTargetSpecs() 返回 0 条")
	}

	var (
		mu     sync.Mutex
		infos  = make([]targetInfo, 0, len(specs))
		full   = make(map[string]string, len(specs)) // id → 完整 flag{...}
		inner  = make(map[string]string, len(specs)) // id → 剥壳后的答案
		errors []string
	)

	for i, s := range specs {
		addr := fmt.Sprintf("%s:%d", *host, *base+i)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errors = append(errors, fmt.Sprintf("靶机 %s 端口 %d 监听失败: %v", s.ID, *base+i, err))
			continue
		}
		url := "http://" + addr
		mu.Lock()
		infos = append(infos, targetInfo{ID: s.ID, Title: s.Title, Desc: s.Desc, URL: url})
		full[s.ID] = s.Flag
		inner[s.ID] = ctfplatform.StripFlagWrapper(s.Flag)
		mu.Unlock()

		h := s.Handler
		go func(id string, ln net.Listener) {
			if err := (&http.Server{Handler: h}).Serve(ln); err != nil {
				log.Printf("[range] 靶机 %s 退出: %v", id, err)
			}
		}(s.ID, ln)
		fmt.Printf("[range] %s %-8s -> %s\n", s.ID, s.Title, url)
	}
	if len(errors) > 0 {
		for _, e := range errors {
			log.Printf("[range] ERROR %s", e)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/targets", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(infos)
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID   string `json:"id"`
			Flag string `json:"flag"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		want := inner[req.ID]
		wantFull := full[req.ID]
		mu.Unlock()
		sub := strings.TrimSpace(req.Flag)
		// 三种等价提交都认：完整外壳 / 剥壳值 / 响应里夹带的完整 flag
		correct := want != "" && (sub == want || sub == wantFull ||
			ctfplatform.StripFlagWrapper(sub) == want)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": req.ID, "correct": correct})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := len(infos)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"targets": n, "ok": n > 0})
	})

	adminAddr := fmt.Sprintf("%s:%d", *host, *admin)
	ln, err := net.Listen("tcp", adminAddr)
	if err != nil {
		log.Fatalf("清单端口 %s 监听失败: %v", adminAddr, err)
	}
	mu.Lock()
	n := len(infos)
	mu.Unlock()
	fmt.Printf("[range] READY targets=%d 清单 http://%s/targets  判分 http://%s/verify\n", n, adminAddr, adminAddr)
	log.Fatal((&http.Server{Handler: mux}).Serve(ln))
}
