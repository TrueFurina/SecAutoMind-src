package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"secautomind-ai/internal/app"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/database"
	"secautomind-ai/internal/logger"
	"secautomind-ai/internal/security"
	"secautomind-ai/internal/termout"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/term"
)

func main() {
	var configPath = flag.String("config", "config.yaml", "Path to the configuration file")
	var httpsBootstrap = flag.Bool("https", false, "Enable HTTPS for the main site; uses an in-memory self-signed certificate when no cert/key is configured")
	var httpBootstrap = flag.Bool("http", false, "Force plain HTTP for the main site, overriding TLS settings in the configuration file")
	var resetAdminPassword = flag.Bool("reset-admin-password", false, "Interactively reset the built-in admin password and exit")
	flag.Parse()

	// 环境变量兼容（便于 systemd/docker 等不传参场景）
	if *httpsBootstrap && *httpBootstrap {
		fmt.Fprintln(os.Stderr, "--http and --https cannot be used together")
		os.Exit(2)
	}
	if !*httpsBootstrap && !*httpBootstrap {
		v := strings.TrimSpace(os.Getenv("SECAUTOMIND_HTTPS"))
		if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
			*httpsBootstrap = true
		}
	}

	// 加载配置
	cp := strings.TrimSpace(*configPath)
	if cp == "" {
		cp = "config.yaml"
	}
	if strings.HasPrefix(cp, "-") {
		fmt.Fprintf(os.Stderr, "Invalid -config path %q.\nIf HTTPS is also needed, use: ./secautomind-ai --https -config config.yaml (-config must be followed by a yaml file path).\n", cp)
		os.Exit(2)
	}
	localConfig, err := config.EnsureLocalConfig(cp)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return
	}

	cfg, err := config.Load(cp)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		return
	}
	if localConfig.Created {
		termout.PrintConfigCreated()
	}

	if *resetAdminPassword {
		if err := runResetAdminPassword(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reset admin password: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *httpBootstrap {
		config.ApplyPlainHTTPBootstrap(cfg)
	} else if *httpsBootstrap {
		config.ApplyDevHTTPSBootstrap(cfg)
	} else {
		// 修复：双击 exe（无任何参数/环境变量）时默认走 HTTP。
		// 原逻辑默认 https + 自签证书，浏览器会弹安全告警且用户双击场景
		// 通常只是本机使用——HTTP 到 127.0.0.1 足够安全，体验更顺滑。
		config.ApplyPlainHTTPBootstrap(cfg)
	}

	port := cfg.Server.Port
	if port <= 0 {
		port = 8080
	}
	scheme := "http"
	if config.MainWebUIUsesHTTPS(&cfg.Server) {
		scheme = "https"
	}
	termout.PrintStartupWebUI(termout.StartupWebUIOptions{
		Scheme:       scheme,
		Port:         port,
		SelfSigned:   scheme == "https" && cfg.Server.TLSAutoSelfSign,
		HTTPRedirect: scheme == "https" && config.ServerHTTPRedirectEnabled(&cfg.Server),
	})

	// 修复：双击 exe（无参数）场景下，服务器就绪后自动打开浏览器，
	// 让用户看到"双击即用"的产品体验，而不是只看到命令行窗口。
	if !*httpsBootstrap && !*httpBootstrap {
		webURL := fmt.Sprintf("%s://127.0.0.1:%d", scheme, port)
		go func(url string) {
			time.Sleep(3 * time.Second) // 等待 HTTP 服务真正监听
			openBrowser(url)
		}(webURL)
		// 产品级体验：绿色版首次运行自动在桌面创建快捷方式（幂等），
		// 用户无需手动建图标——点一次 exe，桌面就有入口。
		go ensureDesktopShortcut()
		fmt.Printf("→ 已在默认浏览器打开管理界面：%s://127.0.0.1:%d （如未弹出请手动访问）\n", scheme, port)
	}

	// MCP 启用且 auth_header_value 为空时，自动生成随机密钥并写回配置
	if err := config.EnsureMCPAuth(cp, cfg); err != nil {
		fmt.Printf("Failed to configure MCP authentication: %v\n", err)
		return
	}
	if cfg.MCP.Enabled {
		config.PrintMCPConfigJSON(cfg.MCP)
	}

	// 初始化日志
	log := logger.New(cfg.Log.Level, cfg.Log.Output)

	// 创建可取消的根 context，用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听系统信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 创建应用
	application, err := app.New(cfg, log, cp)
	if err != nil {
		log.Fatal("应用初始化失败", "error", err)
	}

	// 在后台监听信号
	go func() {
		sig := <-sigCh
		log.Info("收到系统信号，开始优雅关闭: " + sig.String())
		application.Shutdown()
		cancel()
	}()

	// 启动服务器（传入 context 以支持优雅关闭）
	if err := application.RunWithContext(ctx); err != nil {
		// context 取消导致的关闭不视为错误
		if ctx.Err() != nil {
			log.Info("服务器已优雅关闭")
		} else if isPortInUseError(err) {
			// 修复：服务已在运行（端口被占用）——重复双击桌面图标时，
			// 不再 fatal 静默退出，而是打开浏览器聚焦已运行实例（幂等体验）。
			fmt.Printf("SecAutoMind 已在运行，正在打开管理界面…\n")
			openBrowser(fmt.Sprintf("%s://127.0.0.1:%d", scheme, port))
		} else {
			log.Fatal("服务器启动失败", "error", err)
		}
	}
}

func runResetAdminPassword(cfg *config.Config) error {
	dbPath := strings.TrimSpace(cfg.Database.Path)
	if dbPath == "" {
		dbPath = "data/conversations.db"
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("database does not exist: %s; start the service once to initialize it first", dbPath)
		}
		return err
	}

	fmt.Println("Reset built-in admin password")
	fmt.Println()

	password, err := readHiddenPassword("New admin password: ")
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)
	if len(password) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}
	confirm, err := readHiddenPassword("Confirm new password: ")
	if err != nil {
		return err
	}
	if password != strings.TrimSpace(confirm) {
		return fmt.Errorf("passwords do not match")
	}

	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}

	db, err := database.NewDB(dbPath, zap.NewNop())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	admin, err := db.GetRBACUserByUsername("admin")
	if err != nil {
		return fmt.Errorf("built-in admin account was not found; start the service once to initialize it first: %w", err)
	}
	if !admin.IsBuiltin {
		return fmt.Errorf("admin account is not built in; refusing to reset it")
	}
	if err := db.UpdateRBACAdminPassword(hash); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Admin password has been reset.")
	fmt.Println("If the service is running, existing login sessions remain valid until the service restarts or the sessions expire.")
	return nil
}

func readHiddenPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// isPortInUseError 判断错误是否为"端口已被占用"（服务已在运行）。
// Windows: bind: Only one usage of each socket address...
// Linux:   bind: address already in use
func isPortInUseError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address") ||
		strings.Contains(msg, "bind:") && (strings.Contains(msg, "in use") || strings.Contains(msg, "permitted"))
}

// openBrowser 用系统默认浏览器打开 URL（Windows rundll32 / Linux xdg-open）。
func openBrowser(url string) {
	if url == "" {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	} else {
		_ = exec.Command("xdg-open", url).Start()
	}
}

// ensureDesktopShortcut 绿色版产品化：首次运行自动在桌面创建 SecAutoMind 快捷方式。
// - 幂等：桌面已有同名 .lnk 则跳过（不覆盖用户可能修改过的快捷方式）
// - 静默：任何失败（无桌面/无 PowerShell/权限）都不影响服务启动
// - 桌面路径用 [Environment]::GetFolderPath('Desktop')——兼容 OneDrive 重定向
func ensureDesktopShortcut() {
	if runtime.GOOS != "windows" {
		return
	}
	exePath, err := os.Executable()
	if err != nil || exePath == "" {
		return
	}
	if abs, aErr := filepath.Abs(exePath); aErr == nil {
		exePath = abs
	}
	workDir := filepath.Dir(exePath)
	// 单引号包裹路径避免空格问题；脚本内不做二次转义（Windows 路径不含单引号）
	ps := fmt.Sprintf(
		"$d=[Environment]::GetFolderPath('Desktop');"+
			"$l=Join-Path $d 'SecAutoMind.lnk';"+
			"if(Test-Path $l){exit 0};"+
			"$s=(New-Object -ComObject WScript.Shell).CreateShortcut($l);"+
			"$s.TargetPath='%s';"+
			"$s.WorkingDirectory='%s';"+
			"$s.IconLocation='%s,0';"+
			"$s.Description='SecAutoMind - 自主决策多智能体攻防推演平台';"+
			"$s.Save()",
		strings.ReplaceAll(exePath, "'", "''"),
		strings.ReplaceAll(workDir, "'", "''"),
		strings.ReplaceAll(exePath, "'", "''"),
	)
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
}
