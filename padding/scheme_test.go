package padding

import (
	"strings"
	"testing"
)

func TestParseDefault(t *testing.T) {
	scheme := DefaultScheme()

	if scheme.Stop != 6 {
		t.Errorf("stop = %d, want 6", scheme.Stop)
	}
	if scheme.StreamBytes != 12288 {
		t.Errorf("stream_bytes = %d, want 12288", scheme.StreamBytes)
	}
	if DefaultStop != 6 || DefaultStreamBytes != 12288 || MaxPadTarget != 16384 {
		t.Fatalf("unexpected defaults: stop=%d stream_bytes=%d max_pad_target=%d",
			DefaultStop, DefaultStreamBytes, MaxPadTarget)
	}

	// Shared rules: 3, 4, 5. Rules 0-2 are directional only.
	if len(scheme.Rules) != 3 {
		t.Errorf("shared rules count = %d, want 3", len(scheme.Rules))
	}
	if len(scheme.ClientRules) != 3 {
		t.Errorf("client rules count = %d, want 3", len(scheme.ClientRules))
	}
	if len(scheme.ServerRules) != 3 {
		t.Errorf("server rules count = %d, want 3", len(scheme.ServerRules))
	}

	// Control rule: ~40-160 pad-to.
	ctl := scheme.ControlRules
	if len(ctl) != 1 {
		t.Fatalf("ctl segments = %d, want 1", len(ctl))
	}
	if !ctl[0].IsPadTo || ctl[0].MinSize != 40 || ctl[0].MaxSize != 160 {
		t.Errorf("ctl rule = %+v, want pad-to 40-160", ctl[0])
	}

	// Per-stream lookup order: directional override, shared rule, nil.
	cases := []struct {
		name string
		role Role
		idx  int
		min  int
		max  int
		pad  bool
		nil  bool
	}{
		{name: "client idx0", role: RoleClient, idx: 0, min: 80, max: 200, pad: true},
		{name: "client idx1", role: RoleClient, idx: 1, min: 900, max: 1200, pad: true},
		{name: "client idx2", role: RoleClient, idx: 2, min: 500, max: 1200, pad: true},
		{name: "client idx3 shared", role: RoleClient, idx: 3, min: 300, max: 800, pad: true},
		{name: "server idx0", role: RoleServer, idx: 0, min: 2600, max: 4200, pad: true},
		{name: "server idx1", role: RoleServer, idx: 1, min: 700, max: 1400, pad: true},
		{name: "server idx2", role: RoleServer, idx: 2, min: 700, max: 1400, pad: true},
		{name: "server idx5 shared", role: RoleServer, idx: 5, min: 300, max: 800, pad: true},
		{name: "client beyond stop", role: RoleClient, idx: 6, nil: true},
		{name: "server beyond stop", role: RoleServer, idx: 6, nil: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			segs := scheme.GetSegmentsFor(tc.role, tc.idx)
			if tc.nil {
				if segs != nil {
					t.Fatalf("segments = %+v, want nil", segs)
				}
				return
			}
			if len(segs) != 1 {
				t.Fatalf("segments = %+v, want 1", segs)
			}
			if segs[0].MinSize != tc.min || segs[0].MaxSize != tc.max || segs[0].IsPadTo != tc.pad {
				t.Fatalf("segment = %+v, want pad=%v %d-%d", segs[0], tc.pad, tc.min, tc.max)
			}
		})
	}

	// Keepalive config
	if scheme.Keepalive == nil {
		t.Fatal("keepalive config should be present")
	}
	if scheme.Keepalive.IntervalMinMs != 45000 || scheme.Keepalive.IntervalMaxMs != 90000 {
		t.Errorf("keepalive interval = %d-%d, want 45000-90000",
			scheme.Keepalive.IntervalMinMs, scheme.Keepalive.IntervalMaxMs)
	}
	if scheme.Keepalive.SizeMin != 4 || scheme.Keepalive.SizeMax != 8 {
		t.Errorf("keepalive size = %d-%d, want 4-8",
			scheme.Keepalive.SizeMin, scheme.Keepalive.SizeMax)
	}
}

func TestParseDefaultSchemeText(t *testing.T) {
	text := DefaultScheme().Encode()
	for _, key := range []string{"stop=6", "stream_bytes=12288", "ctl=~40-160", "c1=~900-1200", "s0=~2600-4200"} {
		if !strings.Contains(text, key) {
			t.Errorf("default scheme text missing %q:\n%s", key, text)
		}
	}

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("re-parse default scheme: %v", err)
	}
	if scheme.MD5() != DefaultScheme().MD5() {
		t.Error("re-parsed default scheme MD5 differs")
	}
}

func TestDefaultSchemeTextExact(t *testing.T) {
	// The default scheme text is part of the handshake contract (its MD5 is
	// exchanged in SETTINGS), so pin it exactly.
	want := strings.Join([]string{
		"stop=6",
		"stream_bytes=12288",
		"ctl=~40-160",
		"c0=~80-200",
		"c1=~900-1200",
		"c2=~500-1200",
		"s0=~2600-4200",
		"s1=~700-1400",
		"s2=~700-1400",
		"3=~300-800",
		"4=~300-800",
		"5=~300-800",
		"keepalive=45000-90000:4-8",
	}, "\n")
	if got := DefaultScheme().Encode(); got != want {
		t.Fatalf("default scheme text mismatch:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestParseLegacySchemeStillWorks(t *testing.T) {
	// The original session-epoch scheme text must stay parseable. New clients
	// interpret stop/rules per stream, but the syntax is unchanged.
	text := `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
keepalive=30000-60000:4-8`

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse legacy scheme: %v", err)
	}
	if scheme.Stop != 8 {
		t.Errorf("stop = %d, want 8", scheme.Stop)
	}
	if len(scheme.Rules) != 8 {
		t.Errorf("rules count = %d, want 8", len(scheme.Rules))
	}
	// No directional rules in the legacy text.
	if len(scheme.ClientRules) != 0 || len(scheme.ServerRules) != 0 {
		t.Errorf("directional rules = %d/%d, want 0/0", len(scheme.ClientRules), len(scheme.ServerRules))
	}
	// The implicit control rule still applies so control frames are masked.
	if len(scheme.ControlRules) != 1 || !scheme.ControlRules[0].IsPadTo {
		t.Errorf("control rules = %+v, want implicit pad-to", scheme.ControlRules)
	}
	// Legacy shared rules are still returned by the legacy getter and by the
	// role-aware getter for both directions.
	legacy := scheme.GetSegments(0)
	if len(legacy) != 1 || legacy[0].MinSize != 30 || legacy[0].MaxSize != 30 {
		t.Errorf("legacy rule 0 = %+v, want 30-30", legacy)
	}
	if segs := scheme.GetSegmentsFor(RoleServer, 0); len(segs) != 1 || segs[0].MaxSize != 30 {
		t.Errorf("server fallback rule 0 = %+v, want 30-30", segs)
	}
	segs := scheme.GetSegments(2)
	checkCount := 0
	for _, seg := range segs {
		if seg.IsCheck {
			checkCount++
		}
	}
	if checkCount != 4 {
		t.Errorf("rule 2 check count = %d, want 4", checkCount)
	}
	if segs := scheme.GetSegments(8); segs != nil {
		t.Errorf("packet 8 should return nil segments, got %+v", segs)
	}
}

func TestParseBeyondStop(t *testing.T) {
	scheme := DefaultScheme()
	// Packet 6 and beyond are outside the per-stream epoch.
	if segs := scheme.GetSegments(6); segs != nil {
		t.Errorf("packet 6 should return nil segments, got %+v", segs)
	}
	if segs := scheme.GetSegments(100); segs != nil {
		t.Errorf("packet 100 should return nil segments")
	}
	if segs := scheme.GetSegmentsFor(RoleClient, 100); segs != nil {
		t.Errorf("role-aware packet 100 should return nil segments")
	}
}

func TestParseDirectionalPrecedence(t *testing.T) {
	text := `stop=4
0=~10-10
1=~20-20
c0=~30-30
s0=~40-40
s2=~50-50`

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	check := func(name string, role Role, idx, wantMin, wantMax int) {
		t.Helper()
		segs := scheme.GetSegmentsFor(role, idx)
		if len(segs) != 1 {
			t.Fatalf("%s: segments = %+v, want 1", name, segs)
		}
		seg := segs[0]
		if !seg.IsPadTo || seg.MinSize != wantMin || seg.MaxSize != wantMax {
			t.Errorf("%s: segment = %+v, want pad-to %d-%d", name, seg, wantMin, wantMax)
		}
	}

	// Directional override wins over the shared rule with the same index.
	check("client override", RoleClient, 0, 30, 30)
	check("server override", RoleServer, 0, 40, 40)
	// No directional rule -> shared fallback for both directions.
	check("client shared fallback", RoleClient, 1, 20, 20)
	check("server shared fallback", RoleServer, 1, 20, 20)
	// Only the server has an override for index 2.
	if segs := scheme.GetSegmentsFor(RoleClient, 2); segs != nil {
		t.Errorf("client idx2 = %+v, want nil", segs)
	}
	check("server idx2", RoleServer, 2, 50, 50)
	// Beyond stop both directions stop.
	if segs := scheme.GetSegmentsFor(RoleClient, 4); segs != nil {
		t.Errorf("client idx4 = %+v, want nil", segs)
	}

	// The legacy getter ignores directional overrides.
	legacy := scheme.GetSegments(0)
	if len(legacy) != 1 || legacy[0].MinSize != 10 || legacy[0].MaxSize != 10 {
		t.Errorf("legacy GetSegments(0) = %+v, want shared 10-10", legacy)
	}
}

func TestParsePadToSegments(t *testing.T) {
	text := `stop=4
0=~100
1=~10-20
2=~30-40,~50-60
3=~7-7`

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// ~N means N..N.
	segs := scheme.GetSegments(0)
	if len(segs) != 1 || !segs[0].IsPadTo || segs[0].MinSize != 100 || segs[0].MaxSize != 100 {
		t.Errorf("~100 parsed as %+v", segs)
	}
	// ~min-max keeps its range.
	segs = scheme.GetSegments(1)
	if len(segs) != 1 || !segs[0].IsPadTo || segs[0].MinSize != 10 || segs[0].MaxSize != 20 {
		t.Errorf("~10-20 parsed as %+v", segs)
	}
	// Multiple pad-to segments parse, but the writer consumes the first.
	segs = scheme.GetSegments(2)
	if len(segs) != 2 || !segs[0].IsPadTo || !segs[1].IsPadTo {
		t.Errorf("~30-40,~50-60 parsed as %+v", segs)
	}
}

func TestParseSplitSegmentsStillSupported(t *testing.T) {
	text := `stop=3
0=50-50
1=200-300,c,400-500
2=100-200
keepalive=10000-20000:2-4`

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if scheme.Stop != 3 {
		t.Errorf("stop = %d, want 3", scheme.Stop)
	}

	segs := scheme.GetSegments(1)
	if len(segs) != 3 {
		t.Fatalf("rule 1 segments = %d, want 3", len(segs))
	}
	if segs[0].IsPadTo || segs[0].MinSize != 200 || segs[0].MaxSize != 300 {
		t.Errorf("rule 1 segment 0 = %+v, want split 200-300", segs[0])
	}
	if !segs[1].IsCheck {
		t.Error("rule 1 segment 1 should be check")
	}
	if segs[2].MinSize != 400 || segs[2].MaxSize != 500 || segs[2].IsPadTo {
		t.Errorf("rule 1 segment 2 = %+v, want split 400-500", segs[2])
	}

	if scheme.Keepalive == nil {
		t.Fatal("keepalive should be present")
	}
	if scheme.Keepalive.SizeMin != 2 || scheme.Keepalive.SizeMax != 4 {
		t.Errorf("keepalive size = %d-%d, want 2-4", scheme.Keepalive.SizeMin, scheme.Keepalive.SizeMax)
	}
}

func TestParseControlRules(t *testing.T) {
	// Absent -> implicit ctl=~40-160.
	scheme, err := Parse("stop=2\n0=30-30")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(scheme.ControlRules) != 1 || !scheme.ControlRules[0].IsPadTo ||
		scheme.ControlRules[0].MinSize != 40 || scheme.ControlRules[0].MaxSize != 160 {
		t.Errorf("implicit control rule = %+v, want ~40-160", scheme.ControlRules)
	}

	// Explicit override.
	scheme, err = Parse("ctl=~100-100\n0=30-30")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(scheme.ControlRules) != 1 || scheme.ControlRules[0].MinSize != 100 || scheme.ControlRules[0].MaxSize != 100 {
		t.Errorf("explicit control rule = %+v, want ~100-100", scheme.ControlRules)
	}

	// Empty value disables control padding.
	scheme, err = Parse("ctl=\n0=30-30")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if scheme.ControlRules != nil {
		t.Errorf("ctl= should disable control padding, got %+v", scheme.ControlRules)
	}
}

func TestParseStreamBytes(t *testing.T) {
	scheme, err := Parse("stream_bytes=4096\n0=30-30")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if scheme.StreamBytes != 4096 {
		t.Errorf("stream_bytes = %d, want 4096", scheme.StreamBytes)
	}

	// Absent key uses the default budget.
	scheme, err = Parse("0=30-30")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if scheme.StreamBytes != DefaultStreamBytes {
		t.Errorf("default stream_bytes = %d, want %d", scheme.StreamBytes, DefaultStreamBytes)
	}

	if _, err := Parse("stream_bytes=bad"); err == nil {
		t.Error("invalid stream_bytes should return an error")
	}
}

func TestParseNoKeepalive(t *testing.T) {
	text := `stop=2
0=30-30
1=100-200`

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if scheme.Keepalive != nil {
		t.Error("keepalive should be nil when not specified")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"invalid stop":         "stop=bad",
		"invalid rule":         "0=bad",
		"invalid client rule":  "c0=bad",
		"invalid server rule":  "s1=bad",
		"invalid ctl":          "ctl=bad",
		"invalid pad-to":       "3=~bad",
		"empty segment":        "0=30-30,",
		"negative pad-to size": "0=~-5-10",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(text); err == nil {
				t.Fatalf("Parse(%q) = nil error, want error", text)
			}
		})
	}
}

func TestParseUnknownKeysIgnored(t *testing.T) {
	text := `stop=2
future_key=whatever
c-not-a-number=~10-10
sX=~10-10
0=30-30
1=100-200`

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if scheme.Stop != 2 {
		t.Errorf("stop = %d, want 2", scheme.Stop)
	}
	if len(scheme.Rules) != 2 {
		t.Errorf("rules count = %d, want 2", len(scheme.Rules))
	}
	if len(scheme.ClientRules) != 0 || len(scheme.ServerRules) != 0 {
		t.Errorf("unknown directional keys should be ignored, got c=%d s=%d",
			len(scheme.ClientRules), len(scheme.ServerRules))
	}
}

func TestParseComments(t *testing.T) {
	text := `# This is a comment
stop=2
0=30-30
# Another comment
1=100-200`

	scheme, err := Parse(text)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if scheme.Stop != 2 {
		t.Errorf("stop = %d, want 2", scheme.Stop)
	}
	if len(scheme.Rules) != 2 {
		t.Errorf("rules count = %d, want 2", len(scheme.Rules))
	}
}

func TestMD5Consistency(t *testing.T) {
	scheme := DefaultScheme()
	md5a := scheme.MD5()
	md5b := scheme.MD5()
	if md5a != md5b {
		t.Errorf("MD5 should be consistent: %q != %q", md5a, md5b)
	}
	if len(md5a) != 32 {
		t.Errorf("MD5 length = %d, want 32", len(md5a))
	}

	other := DefaultScheme()
	other.Raw = "stop=1"
	if other.MD5() == md5a {
		t.Error("different scheme text should produce a different MD5")
	}
}

func TestRandomInRange(t *testing.T) {
	// Same min/max should return that value
	for i := 0; i < 100; i++ {
		v := RandomInRange(42, 42)
		if v != 42 {
			t.Fatalf("RandomInRange(42,42) = %d, want 42", v)
		}
	}

	// Range should be respected
	for i := 0; i < 1000; i++ {
		v := RandomInRange(10, 20)
		if v < 10 || v > 20 {
			t.Fatalf("RandomInRange(10,20) = %d, out of range", v)
		}
	}
}
