package ctfplatform

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const loginFormHTML = `<html><body>
<form name="login_form" action="index.php" onSubmit="fixLogin()" method="POST">
<input type="text" name="username"/>
<input type="password" name="password"/>
<input type="submit" value="Log In"/>
</form>
</body></html>`

const mysqlErrHTML = `<html><body>Warning: mysql_query(): You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server version</body></html>`

// newLoginServer 模拟带登录表单的后台。
// mode: vuln（引号触发报错）/ safe（永不报错）/ broken（基线就报错）
func newLoginServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	page := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			io.WriteString(w, loginFormHTML)
			return
		}
		_ = r.ParseForm()
		u := r.PostFormValue("username")
		switch mode {
		case "broken":
			io.WriteString(w, mysqlErrHTML)
		case "vuln":
			if strings.ContainsAny(u, "'\"\\") {
				io.WriteString(w, mysqlErrHTML)
				return
			}
			io.WriteString(w, loginFormHTML)
		default:
			io.WriteString(w, loginFormHTML)
		}
	}
	mux.HandleFunc("/admin/", page)
	mux.HandleFunc("/admin/index.php", page)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestClassifySQLError(t *testing.T) {
	cases := []struct {
		name string
		body string
		db   string
		ok   bool
	}{
		{"mysql", "You have an error in your SQL syntax; check the manual", "mysql", true},
		{"mssql", "Unclosed quotation mark after the character string 'x'", "mssql", true},
		{"oracle", "ORA-00933: SQL command not properly ended", "oracle", true},
		{"pgsql", "PostgreSQL query failed: ERROR: syntax error", "pgsql", true},
		{"sqlite", "sqlite3.OperationalError: near \"x\": syntax error", "sqlite", true},
		{"generic", "SQLSTATE[42000]: Syntax error", "generic", true},
		{"normal", `<html><body>Welcome to the site</body></html>`, "", false},
		{"word_sql_only", "we use SQL in the backend", "", false},
	}
	for _, c := range cases {
		db, ok := classifySQLError([]byte(c.body))
		if ok != c.ok || db != c.db {
			t.Errorf("%s: got (%q,%v), want (%q,%v)", c.name, db, ok, c.db, c.ok)
		}
	}
}

func TestDiscoverLoginForms(t *testing.T) {
	srv := newLoginServer(t, "vuln")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cl := webClient(5 * time.Second)
	forms := discoverLoginForms(ctx, cl, srv.URL+"/admin/")
	if len(forms) != 1 {
		t.Fatalf("应发现 1 个登录表单，实际 %d: %+v", len(forms), forms)
	}
	f := forms[0]
	if f.UserField != "username" || f.PassField != "password" {
		t.Errorf("字段解析错误: %+v", f)
	}
	if !strings.HasSuffix(f.Action, "/admin/index.php") {
		t.Errorf("相对 action 未解析为绝对 URL: %q", f.Action)
	}
}

func TestProbeSQLError_DetectsMySQL(t *testing.T) {
	srv := newLoginServer(t, "vuln")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ev := ProbeSQLError(ctx, srv.URL, WebHints{})
	if len(ev) == 0 {
		t.Fatalf("应检出报错型 SQL 注入，实际 0")
	}
	e := ev[0]
	if e.Kind != "sqli_error" || e.Signal != "sqli_error_mysql" {
		t.Errorf("证据字段异常: %+v", e)
	}
	if e.Param != "username" {
		t.Errorf("应记录注入字段 username，实际 %q", e.Param)
	}
	if strings.Contains(e.Detail, "check the manual") {
		t.Errorf("Detail 不应回显报错原文: %q", e.Detail)
	}
}

func TestProbeSQLError_NoFalsePositive(t *testing.T) {
	srv := newLoginServer(t, "safe")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if ev := ProbeSQLError(ctx, srv.URL, WebHints{}); len(ev) != 0 {
		t.Fatalf("不应误报，实际 %+v", ev)
	}
}

func TestProbeSQLError_SkipsBrokenBaseline(t *testing.T) {
	// 基线（良性凭据）本身就报错 → 无法归因于注入，必须跳过
	srv := newLoginServer(t, "broken")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if ev := ProbeSQLError(ctx, srv.URL, WebHints{}); len(ev) != 0 {
		t.Fatalf("基线已报错时不应产出证据，实际 %+v", ev)
	}
}
