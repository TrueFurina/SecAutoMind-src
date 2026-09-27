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
