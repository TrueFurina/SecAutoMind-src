package builtin

import (
	"sort"
	"testing"
)

func TestIsBuiltinTool(t *testing.T) {
	all := GetAllBuiltinTools()
	if len(all) == 0 {
		t.Fatal("GetAllBuiltinTools returned empty")
	}
	for _, name := range all {
		if !IsBuiltinTool(name) {
			t.Errorf("GetAllBuiltinTools contains %q but IsBuiltinTool returns false", name)
		}
	}
	// unknown names must be rejected
	for _, bad := range []string{"", "not_a_tool", "RecordVulnerability", "shell_exec", "___"} {
		if IsBuiltinTool(bad) {
			t.Errorf("IsBuiltinTool(%q) should be false", bad)
		}
	}
}

func TestBuiltinToolsNoDuplicates(t *testing.T) {
	all := GetAllBuiltinTools()
	seen := make(map[string]int, len(all))
	for _, n := range all {
		seen[n]++
	}
	for n, c := range seen {
		if c > 1 {
			t.Errorf("duplicate builtin tool name %q (count %d)", n, c)
		}
	}
}

func TestBuiltinToolKnownConstants(t *testing.T) {
	// a representative sample of the constants must be present and self-consistent
	want := []string{
		ToolRecordVulnerability, ToolUpsertProjectFact, ToolAnalyzeImage,
		ToolWebshellExec, ToolBatchTaskCreate, ToolC2Listener, ToolC2Payload,
	}
	idx := make(map[string]bool)
	for _, n := range GetAllBuiltinTools() {
		idx[n] = true
	}
	sort.Strings(want)
	for _, w := range want {
		if !idx[w] {
			t.Errorf("expected builtin tool %q missing from GetAllBuiltinTools", w)
		}
		if w == "" {
			t.Error("a builtin tool constant is empty")
		}
	}
}
