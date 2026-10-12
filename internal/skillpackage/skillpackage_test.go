package skillpackage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- front matter parse / build round-trip ----------

func TestExtractSkillMDFrontMatterYAML(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantErr  bool
		wantFM   string
		wantBody string
	}{
		{"empty", "", true, "", ""},
		{"no_front_matter", "# Title\nbody", true, "", ""},
		{"unterminated", "---\nname: x\nbody", true, "", ""},
		{
			name:     "ok",
			raw:      "---\nname: foo\ndescription: bar\n---\n# Body\ntext",
			wantErr:  false,
			wantFM:   "name: foo\ndescription: bar",
			wantBody: "# Body\ntext",
		},
		{
			name:     "bom_stripped",
			raw:      "\ufeff---\nname: foo\n---\nbody",
			wantErr:  false,
			wantFM:   "name: foo",
			wantBody: "body",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fm, body, err := ExtractSkillMDFrontMatterYAML([]byte(c.raw))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got fm=%q body=%q", fm, body)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.TrimSpace(fm) != c.wantFM {
				t.Errorf("fm:\n got %q\nwant %q", fm, c.wantFM)
			}
			if body != c.wantBody {
				t.Errorf("body:\n got %q\nwant %q", body, c.wantBody)
			}
		})
	}
}

func TestParseBuildRoundTrip(t *testing.T) {
	m := &SkillManifest{
		Name:          "my-skill",
		Description:   "does a thing",
		License:       "MIT",
		Compatibility: "ctf-agent",
		AllowedTools:  "bash, read",
		Metadata:      map[string]any{"tags": []any{"a", "b"}, "version": "1.2.3"},
	}
	body := "## Usage\n\ncall it.\n\n## Notes\n\ndetail."
	out, err := BuildSkillMD(m, body)
	if err != nil {
		t.Fatalf("BuildSkillMD: %v", err)
	}
	got, gotBody, err := ParseSkillMD(out)
	if err != nil {
		t.Fatalf("ParseSkillMD: %v", err)
	}
	if got.Name != m.Name || got.Description != m.Description || got.License != m.License ||
		got.Compatibility != m.Compatibility || got.AllowedTools != m.AllowedTools {
		t.Errorf("manifest mismatch: %+v vs %+v", got, m)
	}
	if gotBody != strings.TrimSpace(body) {
		t.Errorf("body mismatch:\n got %q\nwant %q", gotBody, strings.TrimSpace(body))
	}
	// metadata (tags + version) round-trips
	if v := versionFromMetadata(got); v != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", v)
	}
	tags := manifestTags(got)
	if len(tags) != 2 || tags[0] != "a" || tags[1] != "b" {
		t.Errorf("tags = %v, want [a b]", tags)
	}
}

func TestBuildSkillMDNil(t *testing.T) {
	if _, err := BuildSkillMD(nil, "x"); err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

// ---------- manifest validation (Agent Skills spec) ----------

func TestValidateAgentSkillManifest(t *testing.T) {
	ok := &SkillManifest{Name: "good-name", Description: "a description"}
	if err := ValidateAgentSkillManifest(ok); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	cases := []struct {
		name string
		m    *SkillManifest
	}{
		{"nil", nil},
		{"empty_name", &SkillManifest{Name: "", Description: "d"}},
		{"empty_desc", &SkillManifest{Name: "x", Description: ""}},
		{"name_too_long", &SkillManifest{Name: strings.Repeat("a", 65), Description: "d"}},
		{"desc_too_long", &SkillManifest{Name: "x", Description: strings.Repeat("a", 1025)}},
		{"uppercase", &SkillManifest{Name: "Bad", Description: "d"}},
		{"bad_char", &SkillManifest{Name: "bad_name", Description: "d"}},
		{"leading_hyphen", &SkillManifest{Name: "-bad", Description: "d"}},
		{"trailing_hyphen", &SkillManifest{Name: "bad-", Description: "d"}},
		{"double_hyphen", &SkillManifest{Name: "bad--name", Description: "d"}},
		{"reserved_anthropic", &SkillManifest{Name: "anthropic-tool", Description: "d"}},
		{"reserved_claude", &SkillManifest{Name: "claude-x", Description: "d"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateAgentSkillManifest(c.m); err == nil {
				t.Fatalf("expected error for %+v", c.m)
			}
		})
	}
}

func TestValidateAgentSkillManifestInPackage(t *testing.T) {
	m := &SkillManifest{Name: "my-skill", Description: "d"}
	if err := ValidateAgentSkillManifestInPackage(m, "my-skill"); err != nil {
		t.Fatalf("expected match, got %v", err)
	}
	if err := ValidateAgentSkillManifestInPackage(m, "other"); err == nil {
		t.Fatal("expected mismatch error when name != dir")
	}
	// empty dir name skips the match check
	if err := ValidateAgentSkillManifestInPackage(m, ""); err != nil {
		t.Fatalf("expected skip, got %v", err)
	}
}

func TestValidateOfficialFrontMatterTopLevelKeys(t *testing.T) {
	valid := "name: x\ndescription: d\nmetadata:\n  version: 1"
	if err := ValidateOfficialFrontMatterTopLevelKeys(valid); err != nil {
		t.Fatalf("expected valid keys, got %v", err)
	}
	bad := "name: x\nfoo: bar"
	if err := ValidateOfficialFrontMatterTopLevelKeys(bad); err == nil {
		t.Fatal("expected error for unsupported key foo")
	}
}

func TestValidateSkillMDPackage(t *testing.T) {
	good := []byte("---\nname: my-skill\ndescription: d\n---\nbody text")
	if err := ValidateSkillMDPackage(good, "my-skill"); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	emptyBody := []byte("---\nname: my-skill\ndescription: d\n---\n")
	if err := ValidateSkillMDPackage(emptyBody, "my-skill"); err == nil {
		t.Fatal("expected error for empty body")
	}
	nameMismatch := []byte("---\nname: other\ndescription: d\n---\nbody")
	if err := ValidateSkillMDPackage(nameMismatch, "my-skill"); err == nil {
		t.Fatal("expected error for name/dir mismatch")
	}
	unsupportedKey := []byte("---\nname: my-skill\ndescription: d\nsecret: 1\n---\nbody")
	if err := ValidateSkillMDPackage(unsupportedKey, "my-skill"); err == nil {
		t.Fatal("expected error for unsupported key")
	}
}

// ---------- path safety (security-relevant) ----------

func TestSafeRelPath(t *testing.T) {
	root := "/skills/my-skill"
	cases := []struct {
		rel     string
		wantErr bool
	}{
		{"", true},
		{".", true},
		{"../escape", true},
		{"a/b/../../escape", true},
		{"/abs", false},
		{"scripts/run.py", false},
		{"SKILL.md", false},
	}
	for _, c := range cases {
		_, err := SafeRelPath(root, c.rel)
		if c.wantErr && err == nil {
			t.Errorf("rel=%q: expected error", c.rel)
		}
		if !c.wantErr && err != nil {
			t.Errorf("rel=%q: unexpected error %v", c.rel, err)
		}
	}
}

// ---------- markdown helpers ----------

func TestSlugifySectionID(t *testing.T) {
	cases := map[string]string{
		"":            "section",
		"My Section":  "my-section",
		"  Trim Me  ": "trim-me",
		"weird#char":  "weirdchar",
		"a--b":        "a--b",
	}
	for in, want := range cases {
		if got := slugifySectionID(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitMarkdownSections(t *testing.T) {
	body := "## First\n\ntext one\n\n## Second\n\ntext two"
	secs := splitMarkdownSections(body)
	if len(secs) != 2 {
		t.Fatalf("want 2 sections, got %d", len(secs))
	}
	if secs[0].Title != "First" || secs[1].Title != "Second" {
		t.Errorf("titles = %q, %q", secs[0].Title, secs[1].Title)
	}
	// no headings -> single _body
	single := splitMarkdownSections("just text")
	if len(single) != 1 || single[0].Title != "_body" {
		t.Errorf("expected _body fallback, got %+v", single)
	}
}

func TestDeriveSectionsFiltersBody(t *testing.T) {
	body := "intro\n\n## Real\n\nx"
	secs := deriveSections(body)
	if len(secs) != 1 || secs[0].ID != "real" {
		t.Errorf("deriveSections = %+v, want [real]", secs)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("hello", 0); got != "hello" {
		t.Errorf("max<=0 should pass through, got %q", got)
	}
	if got := truncateRunes("hello", 3); got != "hel…" {
		t.Errorf("truncate(3) = %q, want hel…", got)
	}
	if got := truncateRunes("hello", 100); got != "hello" {
		t.Errorf("short string unchanged, got %q", got)
	}
}

func TestFindSectionContent(t *testing.T) {
	body := "## Alpha\n\naaa\n\n## Beta\n\nbbb"
	secs := splitMarkdownSections(body)
	if got := findSectionContent(secs, "beta"); !strings.Contains(got, "bbb") {
		t.Errorf("findSectionContent(beta) = %q, want it to contain bbb", got)
	}
	if got := findSectionContent(secs, "alpha"); !strings.Contains(got, "aaa") {
		t.Errorf("findSectionContent(alpha) = %q, want it to contain aaa", got)
	}
	if got := findSectionContent(secs, "missing"); got != "" {
		t.Errorf("missing section should be empty, got %q", got)
	}
}

// ---------- filesystem integration (temp dir) ----------

func writeTempSkill(t *testing.T, root, dir string, md string) string {
	t.Helper()
	skillPath := filepath.Join(root, dir)
	if err := os.MkdirAll(filepath.Join(skillPath, "scripts"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte(md), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "scripts", "run.py"), []byte("print('hi')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return skillPath
}

func TestListSkillSummariesAndLoad(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "skills")
	md := "---\nname: demo\nlicense: MIT\ndescription: demo skill\nmetadata:\n  version: 0.1.0\n---\n## Usage\n\nrun it.\n\n## Notes\n\nmore."
	writeTempSkill(t, root, "demo", md)

	summaries, err := ListSkillSummaries(root)
	if err != nil {
		t.Fatalf("ListSkillSummaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("want 1 summary, got %d", len(summaries))
	}
	s := summaries[0]
	if s.Name != "demo" || s.Version != "0.1.0" || s.ScriptCount != 1 {
		t.Errorf("summary = %+v", s)
	}

	// full load
	v, err := LoadSkill(root, "demo", LoadOptions{Depth: "full"})
	if err != nil {
		t.Fatalf("LoadSkill full: %v", err)
	}
	if len(v.Sections) != 2 {
		t.Errorf("want 2 sections, got %d", len(v.Sections))
	}
	if v.Content != "## Usage\n\nrun it.\n\n## Notes\n\nmore." {
		t.Errorf("full content mismatch: %q", v.Content)
	}

	// summary depth
	vs, err := LoadSkill(root, "demo", LoadOptions{Depth: "summary"})
	if err != nil {
		t.Fatalf("LoadSkill summary: %v", err)
	}
	if !strings.Contains(vs.Content, "Preview (SKILL.md)") {
		t.Errorf("summary missing preview marker: %q", vs.Content)
	}

	// section filter
	vsec, err := LoadSkill(root, "demo", LoadOptions{Section: "notes"})
	if err != nil {
		t.Fatalf("LoadSkill section: %v", err)
	}
	if !strings.Contains(vsec.Content, "more.") {
		t.Errorf("section notes should contain more., got %q", vsec.Content)
	}

	// missing section
	vmiss, err := LoadSkill(root, "demo", LoadOptions{Section: "nope"})
	if err != nil {
		t.Fatalf("LoadSkill missing section: %v", err)
	}
	if !strings.Contains(vmiss.Content, "not found") {
		t.Errorf("missing section should report not found, got %q", vmiss.Content)
	}
}

func TestReadWritePackageFile(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "skills")
	md := "---\nname: demo\ndescription: d\n---\nbody"
	writeTempSkill(t, root, "demo", md)

	if err := WritePackageFile(root, "demo", "scripts/new.txt", []byte("data")); err != nil {
		t.Fatalf("WritePackageFile: %v", err)
	}
	got, err := ReadPackageFile(root, "demo", "scripts/new.txt", 0)
	if err != nil {
		t.Fatalf("ReadPackageFile: %v", err)
	}
	if string(got) != "data" {
		t.Errorf("read back = %q, want data", got)
	}

	// traversal rejected
	if _, err := ReadPackageFile(root, "demo", "../escape", 0); err == nil {
		t.Fatal("expected traversal rejection")
	}

	// list files includes SKILL.md + scripts
	files, err := ListPackageFiles(root, "demo")
	if err != nil {
		t.Fatalf("ListPackageFiles: %v", err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Path)
	}
	if !contains(names, "SKILL.md") || !contains(names, "scripts/new.txt") {
		t.Errorf("ListPackageFiles missing entries: %v", names)
	}
}

func TestSkillsRootFromConfig(t *testing.T) {
	// relative -> resolved against the config file's directory
	got := SkillsRootFromConfig("skills", filepath.Join("etc", "secauto", "config.yaml"))
	want := filepath.Join("etc", "secauto", "skills")
	if got != want {
		t.Errorf("relative: got %q, want %q", got, want)
	}
	// absolute (per this platform) -> passes through unchanged
	abs := filepath.Join(string(os.PathSeparator), "var", "skills")
	if filepath.IsAbs(abs) {
		if got := SkillsRootFromConfig(abs, filepath.Join("etc", "x.yaml")); got != abs {
			t.Errorf("absolute pass-through: got %q, want %q", got, abs)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
