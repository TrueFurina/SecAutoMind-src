package runnerl3

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// scriptedModel 是可脚本化的假 ChatModel：按第几次调用返回预设结果。
type scriptedModel struct {
	id string

	mu          sync.Mutex
	genCalls    int
	streamCalls int

	respond   func(call int) (*schema.Message, error)
	streamOut func(call int) (*schema.StreamReader[*schema.Message], error)
}

func (m *scriptedModel) Generate(ctx context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.mu.Lock()
	m.genCalls++
	n := m.genCalls
	m.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if m.respond == nil {
		return nil, errors.New("scriptedModel: respond 未设置")
	}
	return m.respond(n)
}

func (m *scriptedModel) Stream(ctx context.Context, _ []*schema.Message, _ ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	m.mu.Lock()
	m.streamCalls++
	n := m.streamCalls
	m.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if m.streamOut == nil {
		return nil, errors.New("scriptedModel: streamOut 未设置")
	}
	return m.streamOut(n)
}

func (m *scriptedModel) calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.genCalls
}

func (m *scriptedModel) streamCallsCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamCalls
}

func newFailover(t *testing.T, cooldown time.Duration, ms ...*scriptedModel) (*failoverChatModel, *time.Time) {
	t.Helper()
	now := time.Unix(1700000000, 0)
	entries := make([]*failoverEntry, 0, len(ms))
	for _, m := range ms {
		entries = append(entries, &failoverEntry{id: m.id, mdl: m})
	}
	return &failoverChatModel{
		entries:  entries,
		cooldown: cooldown,
		logger:   nil,
		now:      func() time.Time { return now },
	}, &now
}

func TestFailoverGenerateSwitchesOnTransient(t *testing.T) {
	ch1 := &scriptedModel{id: "amd", respond: func(int) (*schema.Message, error) {
		return nil, &einoopenai.APIError{HTTPStatusCode: 429, Message: "rate limit"}
	}}
	ch2 := &scriptedModel{id: "zhipu", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}
	f, _ := newFailover(t, 300*time.Second, ch1, ch2)

	msg, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil {
		t.Fatalf("期望切到备用通道成功，实际 err=%v", err)
	}
	if msg == nil || msg.Content != "ok" {
		t.Fatalf("返回消息不符：%+v", msg)
	}
	if ch1.calls() != 1 {
		t.Fatalf("主通道应被调用 1 次，实际 %d", ch1.calls())
	}
	if ch2.calls() != 1 {
		t.Fatalf("备用通道应被调用 1 次，实际 %d", ch2.calls())
	}
}

func TestFailoverPermanentErrorDoesNotSwitch(t *testing.T) {
	// 400 = payload 错，换通道一样错 → 不许烧其他通道的免费额度
	ch1 := &scriptedModel{id: "amd", respond: func(int) (*schema.Message, error) {
		return nil, &einoopenai.APIError{HTTPStatusCode: 400, Message: "bad request"}
	}}
	ch2 := &scriptedModel{id: "zhipu", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("never", nil), nil
	}}
	f, _ := newFailover(t, 300*time.Second, ch1, ch2)

	if _, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatalf("400 必须报错，不能静默成功")
	}
	if ch2.calls() != 0 {
		t.Fatalf("永久错误不得触发切通道，备用通道被调用了 %d 次", ch2.calls())
	}
}

func TestFailoverCoolsFailedChannel(t *testing.T) {
	ch1 := &scriptedModel{id: "amd", respond: func(int) (*schema.Message, error) {
		return nil, &einoopenai.APIError{HTTPStatusCode: 429}
	}}
	ch2 := &scriptedModel{id: "zhipu", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}
	f, now := newFailover(t, 300*time.Second, ch1, ch2)

	for i := 0; i < 3; i++ {
		if _, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
			t.Fatalf("第 %d 轮应成功，err=%v", i+1, err)
		}
	}
	if ch1.calls() != 1 {
		t.Fatalf("失败的通道应被冷却、3 轮内只调用 1 次，实际 %d", ch1.calls())
	}
	if ch2.calls() != 3 {
		t.Fatalf("备用通道应承接 3 轮，实际 %d", ch2.calls())
	}

	// 冷却窗口过后，主通道必须重新参与（冷却不是永久拉黑）
	*now = now.Add(301 * time.Second)
	if _, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("冷却结束后应可用，err=%v", err)
	}
	if ch1.calls() != 2 {
		t.Fatalf("冷却结束后主通道应重新被调用，实际 %d", ch1.calls())
	}
}

func TestFailoverAllUnavailableFailsClosed(t *testing.T) {
	// 单通道且瞬时失败 → 冷却 → 后续调用必须报错，绝不 nil,nil 假装成功
	ch1 := &scriptedModel{id: "amd", respond: func(int) (*schema.Message, error) {
		return nil, errors.New("dial tcp: connect: connection refused")
	}}
	f, now := newFailover(t, 300*time.Second, ch1)

	if _, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatalf("通道失败必须报错，不能返回成功")
	}
	// 第二次：主通道仍在冷却 → 无可用通道 → 仍必须报错
	*now = now.Add(10 * time.Second)
	msg, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err == nil {
		t.Fatalf("全通道冷却时必须 fail-closed 报错，实际返回 msg=%+v", msg)
	}
	if msg != nil {
		t.Fatalf("失败时不得返回消息体：%+v", msg)
	}
}

func TestFailoverContextDeadlineNoSwitch(t *testing.T) {
	ch1 := &scriptedModel{id: "amd", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}
	ch2 := &scriptedModel{id: "zhipu", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}
	f, _ := newFailover(t, 300*time.Second, ch1, ch2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Generate(ctx, []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatalf("ctx 已取消必须报错")
	}
	if ch1.calls() != 0 || ch2.calls() != 0 {
		t.Fatalf("ctx 已死不得再打任何通道：ch1=%d ch2=%d", ch1.calls(), ch2.calls())
	}
}

func TestFailoverSuccessClearsCooldown(t *testing.T) {
	// 主通道先失败被冷却，冷却期内若它被直接调用成功（例如冷却结束后），冷却状态应被清除
	call := 0
	ch1 := &scriptedModel{id: "amd", respond: func(int) (*schema.Message, error) {
		call++
		if call == 1 {
			return nil, &einoopenai.APIError{HTTPStatusCode: 503}
		}
		return schema.AssistantMessage("recovered", nil), nil
	}}
	f, now := newFailover(t, 300*time.Second, ch1)

	if _, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatalf("单通道失败必须报错")
	}
	*now = now.Add(301 * time.Second)
	msg, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil || msg == nil || msg.Content != "recovered" {
		t.Fatalf("恢复后应成功：msg=%+v err=%v", msg, err)
	}
	if !f.entries[0].ready(*now) {
		t.Fatalf("成功后应清除该通道的冷却标记")
	}
}

func TestFailoverStreamSwitchesOnTransient(t *testing.T) {
	ch1 := &scriptedModel{id: "amd", streamOut: func(int) (*schema.StreamReader[*schema.Message], error) {
		return nil, errors.New("connection reset by peer")
	}}
	ch2 := &scriptedModel{id: "zhipu", streamOut: func(int) (*schema.StreamReader[*schema.Message], error) {
		return nil, nil // 建流成功（本测试只验证切换，不消费 reader）
	}}
	f, _ := newFailover(t, 300*time.Second, ch1, ch2)

	if _, err := f.Stream(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err != nil {
		t.Fatalf("建流应切到备用通道成功，err=%v", err)
	}
	if ch1.streamCallsCount() != 1 || ch2.streamCallsCount() != 1 {
		t.Fatalf("切换未发生：ch1=%d ch2=%d", ch1.streamCallsCount(), ch2.streamCallsCount())
	}
}

func TestFailoverSingleChannelParity(t *testing.T) {
	// 单通道成功 → 与旧行为一致（成功即返回）
	ok := &scriptedModel{id: "only", respond: func(int) (*schema.Message, error) {
		return schema.AssistantMessage("ok", nil), nil
	}}
	f, _ := newFailover(t, 300*time.Second, ok)
	msg, err := f.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")})
	if err != nil || msg == nil || msg.Content != "ok" {
		t.Fatalf("单通道成功路径回归：msg=%+v err=%v", msg, err)
	}

	// 单通道永久错误 → 原样返回错误（不包装成「全部通道失败」的语义漂移也无害，
	// 但必须是 error，不能吞）
	bad := &scriptedModel{id: "only", respond: func(int) (*schema.Message, error) {
		return nil, &einoopenai.APIError{HTTPStatusCode: 400}
	}}
	f2, _ := newFailover(t, 300*time.Second, bad)
	if _, err := f2.Generate(context.Background(), []*schema.Message{schema.UserMessage("hi")}); err == nil {
		t.Fatalf("单通道 400 必须报错")
	}
}
