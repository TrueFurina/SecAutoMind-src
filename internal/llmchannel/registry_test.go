package llmchannel

import (
	"context"
	"errors"
	"fmt"
	"testing"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
)

func TestBuiltinOrderSanity(t *testing.T) {
	order := BuiltinOrder()
	if len(order) < 5 {
		t.Fatalf("内置通道数 = %d，太少（清单被误删）", len(order))
	}
	seen := map[string]bool{}
	for _, bc := range order {
		if bc.ID == "" {
			t.Fatalf("内置通道缺 ID: %+v", bc)
		}
		if bc.BaseURL == "" {
			t.Fatalf("通道 %s 缺 BaseURL", bc.ID)
		}
		if !bc.Anonymous && bc.KeyEnv == "" {
			t.Fatalf("通道 %s 非匿名却没写 KeyEnv", bc.ID)
		}
		if bc.Anonymous && bc.KeyEnv != "" {
			t.Fatalf("通道 %s 匿名却写了 KeyEnv（矛盾）", bc.ID)
		}
		if bc.BaseURL == "" || bc.BaseURL[0:4] != "http" {
			t.Fatalf("通道 %s BaseURL 非 http(s): %q", bc.ID, bc.BaseURL)
		}
		if seen[bc.ID] {
			t.Fatalf("通道 ID 重复: %s", bc.ID)
		}
		seen[bc.ID] = true
	}
	// 事故主角的通道必须在列（否则 P0-4 的意义没了）
	if !seen["amd"] || !seen["zhipu"] {
		t.Fatalf("内置清单缺关键通道（amd=%v zhipu=%v）", seen["amd"], seen["zhipu"])
	}
	// 不限量的 zhipu 必须排在限流最凶的 amd 之前
	if idxOf(order, "zhipu") > idxOf(order, "amd") {
		t.Fatalf("优先级错：zhipu(%d) 应排在 amd(%d) 之前", idxOf(order, "zhipu"), idxOf(order, "amd"))
	}
}

func idxOf(list []BuiltinChannel, id string) int {
	for i, bc := range list {
		if bc.ID == id {
			return i
		}
	}
	return -1
}

func TestResolvePrimaryFirstAndDedup(t *testing.T) {
	lookup := func(string) string { return "" } // 一个 key 都没有 → 只剩匿名通道
	primary := &Channel{ID: "primary", BaseURL: "https://primary.example/v1", Model: "m0", APIKey: "k"}
	got := Resolve(primary, Options{KeyLookup: lookup})
	if len(got) == 0 || got[0].ID != "primary" {
		t.Fatalf("主通道必须排第一：%+v", got)
	}
	// 无 key 的付费/免费通道一律不进列表（规则 4）
	for _, c := range got {
		if !isAnonymous(c.ID) && c.ID != "primary" {
			t.Fatalf("无 key 通道不该进列表: %s", c.ID)
		}
	}
	// 去重：主通道若是 zhipu 同端点同模型，内置 zhipu 不得重复出现
	dupPrimary := &Channel{ID: "primary", BaseURL: builtinOrder[0].BaseURL, Model: builtinOrder[0].Model, APIKey: "k"}
	got2 := Resolve(dupPrimary, Options{KeyLookup: func(string) string { return "x" }})
	count := 0
	for _, c := range got2 {
		if c.ID == "zhipu" {
			count++
		}
	}
	if count != 0 {
		t.Fatalf("与主通道同端点同模型的内置通道应被去重，实际 %d 个", count)
	}
}

func isAnonymous(id string) bool {
	for _, bc := range builtinOrder {
		if bc.ID == id {
			return bc.Anonymous
		}
	}
	return false
}

func TestResolveSkipsNoKeyChannels(t *testing.T) {
	// 只给 zhipu 与 amd 发 key
	keys := map[string]string{"ZHIPU_API_KEY": "zk", "AMD_API_KEY": "ak"}
	got := Resolve(nil, Options{KeyLookup: func(k string) string { return keys[k] }})
	ids := idsOf(got)
	if len(ids) < 2 {
		t.Fatalf("应至少拿到 zhipu+amd+匿名通道，实际 %v", ids)
	}
	for _, want := range []string{"zhipu", "amd"} {
		if !contains(ids, want) {
			t.Fatalf("有 key 的通道 %s 应进列表，实际 %v", want, ids)
		}
	}
	if contains(ids, "modelscope") {
		t.Fatalf("无 key 的 modelscope 不该进列表：%v", ids)
	}
}

func TestResolveExplicitOrder(t *testing.T) {
	keys := func(string) string { return "k" }
	got := Resolve(nil, Options{Only: []string{"amd", "zhipu"}, KeyLookup: keys})
	ids := idsOf(got)
	if len(ids) != 2 || ids[0] != "amd" || ids[1] != "zhipu" {
		t.Fatalf("显式顺序未生效：%v（应为 [amd zhipu]）", ids)
	}
	// 未识别的 ID 静默忽略（不塞未知通道）
	got2 := Resolve(nil, Options{Only: []string{"nope", "zhipu"}, KeyLookup: keys})
	if ids := idsOf(got2); len(ids) != 1 || ids[0] != "zhipu" {
		t.Fatalf("未知 ID 应忽略，实际 %v", ids)
	}
}

func TestParseChannelIDs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"zhipu,amd", []string{"zhipu", "amd"}},
		{"zhipu\n amd", []string{"zhipu", "amd"}},
		{" amd , , zhipu ", []string{"amd", "zhipu"}},
	}
	for _, c := range cases {
		got := ParseChannelIDs(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("ParseChannelIDs(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("ParseChannelIDs(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestIsTransient(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"429 限流", &einoopenai.APIError{HTTPStatusCode: 429, Message: "rate"}, true},
		{"402 额度耗尽", &einoopenai.APIError{HTTPStatusCode: 402}, true},
		{"401 key 无效", &einoopenai.APIError{HTTPStatusCode: 401}, true},
		{"403 鉴权", &einoopenai.APIError{HTTPStatusCode: 403}, true},
		{"404 模型不在该通道", &einoopenai.APIError{HTTPStatusCode: 404}, true},
		{"400 payload 错", &einoopenai.APIError{HTTPStatusCode: 400}, false},
		{"500", &einoopenai.APIError{HTTPStatusCode: 500}, true},
		{"503", &einoopenai.APIError{HTTPStatusCode: 503}, true},
		{"408 超时", &einoopenai.APIError{HTTPStatusCode: 408}, true},
		{"连接被拒", errors.New("dial tcp: connect: connection refused"), true},
		{"无此主机", errors.New("dial tcp: lookup foo: no such host"), true},
		{"i/o 超时", errors.New("read tcp: i/o timeout"), true},
		{"EOF", errors.New("Post \"https://x/v1/chat/completions\": EOF"), true},
		{"连接复位", errors.New("connection reset by peer"), true},
		{"TLS 握手", errors.New("tls handshake timeout"), true},
		{"包装后仍识别", fmt.Errorf("call model: %w", &einoopenai.APIError{HTTPStatusCode: 429}), true},
		{"未知错误保守不切", errors.New("something weird"), false},
		{"解析失败不切", errors.New("unmarshal openai response: invalid character"), false},
	}
	for _, c := range cases {
		if got := IsTransient(c.err); got != c.want {
			t.Errorf("%s: IsTransient = %v, want %v", c.name, got, c.want)
		}
	}

	// 调用方 ctx 已死 → 不切（那是我们的预算，不是通道的锅）
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if IsTransient(ctx.Err()) {
		t.Errorf("context.Canceled 不应触发切通道")
	}
	deadlineCtx, dcancel := context.WithTimeout(context.Background(), 0)
	defer dcancel()
	<-deadlineCtx.Done()
	if IsTransient(deadlineCtx.Err()) {
		t.Errorf("context.DeadlineExceeded 不应触发切通道")
	}
}

func idsOf(list []Channel) []string {
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.ID)
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
