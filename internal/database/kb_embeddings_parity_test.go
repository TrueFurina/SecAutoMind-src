package database

// knowledge_embeddings 双迁移的行为等价锁（2026-11-10 审计发现登记）。
//
// 背景：同一张表的三列补建存在**两份实现**——
//   ① internal/database/database.go 的 (*DB).migrateKnowledgeEmbeddingsColumns（启动链）
//   ② internal/knowledge/schema_migrate.go 的 EnsureKnowledgeEmbeddingsSchema（indexer 调用）
// 两份列清单今日逐字一致（非现行 bug），但"改一处忘另一处"是典型漂移形态。
// 本测试不比对源码文本（脆），而是**行为等价**：同一张基表分别经两套迁移，
// 最终 pragma 列集合必须一致——任何一侧单独加列/改名，这里立刻红。
// 彻底收敛（一处委托另一处）需跨包依赖方向决策，登记为待拍板技术债，不在本测试范围。

import (
	"database/sql"
	"sort"
	"testing"

	"secautomind-ai/internal/knowledge"
)

func freshKbEmbeddingsDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("打开内存 sqlite 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// 最小基表：两套迁移都只关心"表存在 + 补三列"
	if _, err := db.Exec(`CREATE TABLE knowledge_embeddings (
		id INTEGER PRIMARY KEY,
		chunk_id TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		t.Fatalf("建基表失败: %v", err)
	}
	return db
}

func tableColumns(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info('knowledge_embeddings')`)
	if err != nil {
		t.Fatalf("读列清单失败: %v", err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("扫描列名失败: %v", err)
		}
		cols = append(cols, c)
	}
	sort.Strings(cols)
	return cols
}

func TestKnowledgeEmbeddingsDualMigrationParity(t *testing.T) {
	dbA := freshKbEmbeddingsDB(t)
	dbB := freshKbEmbeddingsDB(t)

	// 路径 A：database 包内启动链那份
	if err := (&DB{DB: dbA}).migrateKnowledgeEmbeddingsColumns(); err != nil {
		t.Fatalf("database 侧迁移失败: %v", err)
	}
	// 路径 B：knowledge 包 indexer 调的那份
	if err := knowledge.EnsureKnowledgeEmbeddingsSchema(dbB); err != nil {
		t.Fatalf("knowledge 侧迁移失败: %v", err)
	}

	a, b := tableColumns(t, dbA), tableColumns(t, dbB)
	if len(a) != len(b) {
		t.Fatalf("两套迁移收敛出不同列集合：database=%v knowledge=%v —— 改一处忘另一处的实锤，须同步两份清单", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("两套迁移第 %d 列不一致：database=%v knowledge=%v", i, a, b)
		}
	}

	// 反向对照：三列必须真的都被补上（防"两边同时漏掉同一列"却仍相等的假绿）
	want := map[string]bool{"sub_indexes": false, "embedding_model": false, "embedding_dim": false}
	for _, c := range a {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for col, seen := range want {
		if !seen {
			t.Fatalf("列 %q 未被任一迁移补上（等价但都缺=假绿）", col)
		}
	}
}
