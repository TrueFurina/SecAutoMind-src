package projectprompt

import (
	"strings"
	"testing"

	"secautomind-ai/internal/mcp/builtin"
)

func TestFactRecordingIncrementalRhythmMarkdown(t *testing.T) {
	base := FactRecordingIncrementalRhythmMarkdown(false, false)
	if !strings.Contains(base, "边渗透边记录") {
		t.Errorf("core rhythm missing: %q", base)
	}
	if strings.Contains(base, "由协调者及时写入") {
		t.Error("coordinator suffix should be absent when coordinator=false")
	}
	coord := FactRecordingIncrementalRhythmMarkdown(true, false)
	if !strings.Contains(coord, "由协调者及时写入") {
		t.Error("coordinator suffix should appear when coordinator=true")
	}
	sub := FactRecordingIncrementalRhythmMarkdown(false, true)
	if !strings.Contains(sub, "待落库") {
		t.Error("sub-agent suffix should appear when subAgent=true")
	}
}

func TestFactRecordingBlackboardSectionReferencesBuiltins(t *testing.T) {
	s := FactRecordingBlackboardSection(false)
	for _, tool := range []string{
		builtin.ToolUpsertProjectFact, builtin.ToolRecordVulnerability,
		builtin.ToolGetProjectFact, builtin.ToolListVulnerabilities,
		builtin.ToolDeprecateProjectFact,
	} {
		if !strings.Contains(s, tool) {
			t.Errorf("blackboard section missing builtin tool constant %q", tool)
		}
	}
	// severity vocabulary present
	if !strings.Contains(s, "critical / high / medium / low / info") {
		t.Error("severity vocabulary missing")
	}
}

func TestFactRecordingBlackboardSectionMarkdownEquivalent(t *testing.T) {
	md := FactRecordingBlackboardSectionMarkdown(false)
	if !strings.Contains(md, "get_project_fact(fact_key)") {
		t.Error("markdown variant should reference get_project_fact literally")
	}
	// coordinator delegate branch
	if !strings.Contains(FactRecordingBlackboardSectionMarkdown(true), "协调者") {
		t.Error("markdown coordinator variant should mention coordinator")
	}
}

func TestFactRecordingSubAgentSection(t *testing.T) {
	s := FactRecordingSubAgentSection()
	if !strings.Contains(s, "边渗透边记录") || !strings.Contains(s, "待落库") {
		t.Errorf("sub-agent section incomplete: %q", s)
	}
}

func TestFactEdgeAndGuidanceBlocks(t *testing.T) {
	if strings.TrimSpace(FactEdgeRecordingGuidance()) == "" {
		t.Error("edge guidance block empty")
	}
	if strings.TrimSpace(FactRecordingGuidanceBlock()) == "" {
		t.Error("guidance block empty")
	}
	if !strings.Contains(FactRecordingGuidanceBlock(), "summary") {
		t.Error("guidance block should mention summary field")
	}
}

func TestShellExecGuidance(t *testing.T) {
	if strings.TrimSpace(ShellExecExecuteGuidanceSection()) == "" {
		t.Error("shell exec guidance empty")
	}
	if !strings.Contains(ShellExecExecuteGuidanceReconSuffix(), "subfinder") {
		t.Error("recon suffix should mention subfinder")
	}
}

// TestCTFGovernanceSection 锁死 P0-1 治理段的核心契约（2026-10-25）：
// 六模板一个不少、IO 契约与 not_applicable 语义在场、四条纪律齐全。
// 防重构时把「模板优先」悄悄删掉——那正是 AICrypto 实证的头号失败模式。
func TestCTFGovernanceSection(t *testing.T) {
	s := CTFGovernanceSection()
	if strings.TrimSpace(s) == "" {
		t.Fatal("CTF governance section empty")
	}
	for _, want := range []string{
		// 六模板 + IO 契约
		"t1_coppersmith.py", "t2_ecdsa_hnp.py", "t3_truncated_lfsr.py",
		"t4_boneh_durfee.py", "t5_dlp_bsgs_ph.py", "t6_hastad_broadcast.py",
		"scripts/ctf_sage/", "stdin", "not_applicable",
		// 四条纪律
		"前提检查", "禁网", "flag", "降级",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("governance section missing %q", want)
		}
	}
}
