package app

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"secautomind-ai/internal/authctx"
	"secautomind-ai/internal/config"
	"secautomind-ai/internal/database"
	"secautomind-ai/internal/einoobserve"
	"secautomind-ai/internal/security"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// mcpHandlerWithAuth 在鉴权通过后转发到 MCP 处理；若配置了 auth_header 则校验请求头，否则直接放行
func (a *App) mcpHandlerWithAuth(w http.ResponseWriter, r *http.Request) {
	cfg := a.config.MCP
	if authHeader := strings.TrimSpace(r.Header.Get("Authorization")); len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		if session, ok := a.auth.ValidateToken(strings.TrimSpace(authHeader[7:])); ok && session.Permissions["mcp:execute"] {
			principal := authctx.NewPrincipalWithScopes(session.UserID, session.Username, session.Scope, session.Permissions, session.PermissionScopes)
			a.mcpServer.HandleHTTP(w, r.WithContext(authctx.WithPrincipal(r.Context(), principal)))
			return
		}
	}
	if !cfg.AllowGlobalAccess || strings.TrimSpace(cfg.AuthHeader) == "" || strings.TrimSpace(cfg.AuthHeaderValue) == "" {
		http.Error(w, "use an authorized user bearer token; global MCP service access is disabled", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(cfg.AuthHeader)), []byte(cfg.AuthHeaderValue)) != 1 {
		a.logger.Logger.Debug("MCP 鉴权失败：header 缺失或值不匹配", zap.String("header", cfg.AuthHeader))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	permissions := make(map[string]bool, len(security.PermissionCatalog))
	for permission := range security.PermissionCatalog {
		permissions[permission] = true
	}
	principal := authctx.NewPrincipal("service:mcp", "mcp-service", database.RBACScopeAll, permissions)
	r = r.WithContext(authctx.WithPrincipal(r.Context(), principal))
	a.mcpServer.HandleHTTP(w, r)
}

// Run 启动应用（向后兼容，不支持优雅关闭）

// Run 启动应用（向后兼容，不支持优雅关闭）
func (a *App) Run() error {
	return a.RunWithContext(context.Background())
}

// RunWithContext 启动应用，支持通过 context 取消来优雅关闭

// RunWithContext 启动应用，支持通过 context 取消来优雅关闭
func (a *App) RunWithContext(ctx context.Context) error {
	// 启动MCP服务器（如果启用）
	var mcpServer *http.Server
	if a.config.MCP.Enabled {
		mcpAddr := fmt.Sprintf("%s:%d", a.config.MCP.Host, a.config.MCP.Port)
		a.logger.Info("启动MCP服务器", zap.String("address", mcpAddr))

		mux := http.NewServeMux()
		mux.HandleFunc("/mcp", a.mcpHandlerWithAuth)

		mcpServer = &http.Server{Addr: mcpAddr, Handler: mux}
		go func() {
			if err := mcpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				a.logger.Error("MCP服务器启动失败", zap.Error(err))
			}
		}()
	}

	// 启动主服务器（可选 HTTPS + HTTP/2，见 config server.tls_*）
	addr := fmt.Sprintf("%s:%d", a.config.Server.Host, a.config.Server.Port)
	tlsMode, tlsConf, certFile, keyFile, tlsErr := prepareMainServerTLS(&a.config.Server)
	if tlsErr != nil {
		return tlsErr
	}

	srv := &http.Server{Addr: addr, Handler: a.router}
	var mainMux *mainServerMux
	httpRedirect := config.ServerHTTPRedirectEnabled(&a.config.Server)
	if tlsMode != mainTLSOff {
		srv.TLSConfig = tlsConf
		if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
			return fmt.Errorf("主服务 HTTP/2 配置失败: %w", err)
		}
		switch tlsMode {
		case mainTLSFromFiles:
			a.logger.Debug("启动 HTTPS 主服务（已启用 HTTP/2 协商）",
				zap.String("address", addr),
				zap.String("cert", certFile),
			)
		case mainTLSInMemorySelfSigned:
			a.logger.Debug("启动 HTTPS 主服务（内存自签证书，仅测试；已启用 HTTP/2 协商）",
				zap.String("address", addr),
			)
		}
		if httpRedirect {
			a.logger.Debug("已启用 HTTP→HTTPS 自动跳转（同端口嗅探分流）", zap.String("address", addr))
		}
	} else {
		a.logger.Debug("启动 HTTP 主服务", zap.String("address", addr))
	}

	// 监听 context 取消，优雅关闭 HTTP 服务器
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if mainMux != nil {
			if err := mainMux.Shutdown(shutdownCtx); err != nil {
				a.logger.Error("HTTP/HTTPS 分流服务器关闭失败", zap.Error(err))
			}
		} else if err := srv.Shutdown(shutdownCtx); err != nil {
			a.logger.Error("HTTP服务器关闭失败", zap.Error(err))
		}
		if mcpServer != nil {
			if err := mcpServer.Shutdown(shutdownCtx); err != nil {
				a.logger.Error("MCP服务器关闭失败", zap.Error(err))
			}
		}
	}()

	var err error
	switch {
	case tlsMode != mainTLSOff && httpRedirect:
		var tlsConfReady *tls.Config
		tlsConfReady, err = ensureMainTLSConfigCerts(tlsMode, tlsConf, certFile, keyFile)
		if err != nil {
			return fmt.Errorf("加载 TLS 证书: %w", err)
		}
		srv.TLSConfig = tlsConfReady
		var ln net.Listener
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		mainMux = newMainServerMux(ln, srv, portFromListenAddr(addr), a.logger.Logger)
		err = mainMux.Serve()
	case tlsMode == mainTLSOff:
		err = srv.ListenAndServe()
	case tlsMode == mainTLSFromFiles:
		err = srv.ListenAndServeTLS(certFile, keyFile)
	case tlsMode == mainTLSInMemorySelfSigned:
		var ln net.Listener
		ln, err = tls.Listen("tcp", addr, srv.TLSConfig)
		if err == nil {
			err = srv.Serve(ln)
		}
	default:
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown 关闭应用

// Shutdown 关闭应用
func (a *App) Shutdown() {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = einoobserve.ShutdownOtel(shutdownCtx)
	shutdownCancel()
	if a.alertCancel != nil {
		a.alertCancel()
		a.alertCancel = nil
	}

	// 停止 CTF 平台轮询器（决赛自动解题；默认关闭，仅 CTF_POLL_ENABLED=true 时存在）
	if a.ctfPollCancel != nil {
		a.ctfPollCancel()
		a.ctfPollCancel = nil
	}

	// 停止钉钉/飞书长连接
	a.robotMu.Lock()
	if a.dingCancel != nil {
		a.dingCancel()
		a.dingCancel = nil
	}
	if a.larkCancel != nil {
		a.larkCancel()
		a.larkCancel = nil
	}
	a.robotMu.Unlock()

	a.shutdownC2()

	// 停止所有外部MCP客户端
	if a.externalMCPMgr != nil {
		a.externalMCPMgr.StopAll()
	}

	// 关闭知识库数据库连接（如果使用独立数据库）
	if a.knowledgeDB != nil {
		if err := a.knowledgeDB.Close(); err != nil {
			a.logger.Logger.Warn("关闭知识库数据库连接失败", zap.Error(err))
		}
	}

	// 关闭主数据库连接
	if a.db != nil {
		if err := a.db.Close(); err != nil {
			a.logger.Logger.Warn("关闭主数据库连接失败", zap.Error(err))
		}
	}
}

// startRobotConnections 根据当前配置启动钉钉/飞书长连接（不先关闭已有连接，仅用于首次启动）
