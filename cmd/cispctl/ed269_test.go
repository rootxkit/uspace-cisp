package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/vectors"
)

func convert(t *testing.T, stdin []byte, args ...string) (int, []byte, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runIO(context.Background(), append([]string{"ed269", "convert"}, args...), nil, bytes.NewReader(stdin), &stdout, &stderr, time.Now())
	return code, stdout.Bytes(), stderr.String()
}

func jsonValue(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return v
}

// The ed318_roundtrip.json mapping cases (to_ed269 and from_ed269)
// through convert both ways: each mapped output equals the vector's by
// value, each refusal names the vector's field and phrase on stderr with
// exit 1, and a from_ed269 output converts back to its input.
func TestVectorsED318RoundtripConvert(t *testing.T) {
	f := vectors.Load(t, "ed318_roundtrip.json")
	ran := 0
	f.RunOwned(t, "cisp", func(t *testing.T, c vectors.Case) {
		var in struct {
			Kind          string          `json:"kind"`
			Document      json.RawMessage `json:"document"`
			ED269Document json.RawMessage `json:"ed269_document"`
			Lang          string          `json:"lang"`
		}
		var exp struct {
			Mapped         *bool           `json:"mapped"`
			ED269          json.RawMessage `json:"ed269"`
			ED318          json.RawMessage `json:"ed318"`
			FieldEndsWith  string          `json:"field_endswith"`
			ReasonContains string          `json:"reason_contains"`
		}
		// Not c.Decode: the other kinds of case carry members this
		// adapter does not read.
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(c.Expected, &exp); err != nil {
			t.Fatal(err)
		}
		lang := []string{}
		if in.Lang != "" {
			lang = []string{"--lang", in.Lang}
		}
		switch in.Kind {
		case "to_ed269":
			ran++
			code, out, errOut := convert(t, in.Document, append([]string{"--to", "ed269"}, lang...)...)
			if exp.Mapped == nil || !*exp.Mapped {
				if code != exitFailed || len(out) != 0 || !strings.Contains(errOut, exp.FieldEndsWith+": ") || !strings.Contains(errOut, exp.ReasonContains) {
					t.Fatalf("convert = %d %q, want %s and %q on stderr", code, errOut, exp.FieldEndsWith, exp.ReasonContains)
				}
				return
			}
			if code != exitOK || !reflect.DeepEqual(jsonValue(t, out), jsonValue(t, exp.ED269)) {
				t.Fatalf("convert = %d %q\n got %s\nwant %s", code, errOut, out, exp.ED269)
			}
		case "from_ed269":
			ran++
			code, out, errOut := convert(t, in.ED269Document, append([]string{"--to", "ed318"}, lang...)...)
			if code != exitOK || !reflect.DeepEqual(jsonValue(t, out), jsonValue(t, exp.ED318)) {
				t.Fatalf("convert = %d %q\n got %s\nwant %s", code, errOut, out, exp.ED318)
			}
			code, back, errOut := convert(t, out, append([]string{"--to", "ed269"}, lang...)...)
			if code != exitOK {
				t.Fatalf("back = %d %q", code, errOut)
			}
			a, pa := ed269.Parse(back, ed269.Limits{})
			b, pb := ed269.Parse(in.ED269Document, ed269.Limits{})
			if pa != nil || pb != nil {
				t.Fatal(pa, pb)
			}
			ea, _ := ed269.Export(a)
			eb, _ := ed269.Export(b)
			if !reflect.DeepEqual(jsonValue(t, ea), jsonValue(t, eb)) {
				t.Errorf("back differs:\n got %s\nwant %s", ea, eb)
			}
		}
	})
	if ran != 7 {
		t.Errorf("%d mapping cases ran; ed318_roundtrip.json has 7", ran)
	}
}

func validED269File(t *testing.T) []byte {
	t.Helper()
	for _, c := range vectors.Load(t, "ed269_parse.json").Cases {
		if c.Name == "valid-file-round-trips-unchanged" {
			var in struct {
				Document json.RawMessage `json:"document"`
			}
			if err := json.Unmarshal(c.Input, &in); err != nil {
				t.Fatal(err)
			}
			return in.Document
		}
	}
	t.Fatal("no valid file")
	return nil
}

// The valid vector file does not map (TST003 has no authority): exit 1
// naming it; without TST003 it maps, with the carried members warned of
// on stderr and exit 0 (E-01).
func TestConvertRefusesAndWarns(t *testing.T) {
	file := validED269File(t)
	code, out, errOut := convert(t, file, "--to", "ed318")
	if code != exitFailed || len(out) != 0 || !strings.Contains(errOut, "features[2].zoneAuthority: ") {
		t.Fatalf("valid file = %d %q", code, errOut)
	}
	var d map[string]any
	if err := json.Unmarshal(file, &d); err != nil {
		t.Fatal(err)
	}
	zones := d["features"].([]any)
	d["features"] = append(append([]any{}, zones[:2]...), zones[3:]...)
	without, _ := json.Marshal(d)
	code, out, errOut = convert(t, without, "--to", "ed318")
	if code != exitOK || !strings.Contains(errOut, "warning: features[1].properties.extendedProperties.ed269.") {
		t.Fatalf("without TST003 = %d %q", code, errOut)
	}
	if !strings.Contains(string(out), `"lang":"ka"`) {
		t.Errorf("the default language is not ka: %s", out)
	}
}

func TestConvertProblemsAndUsage(t *testing.T) {
	// Every problem of a refused file is listed, one per line.
	code, _, errOut := convert(t, []byte(`{"features":[{"identifier":"TOOLONG01"}]}`), "--to", "ed318")
	if code != exitFailed || strings.Count(errOut, "\n") < 2 || !strings.Contains(errOut, "features[0].identifier: ") {
		t.Fatalf("refused = %d %q", code, errOut)
	}
	// ED-318 that does not parse names its problems.
	code, _, errOut = convert(t, []byte(`{"type":"FeatureCollection"}`), "--to", "ed269")
	if code != exitFailed || !strings.Contains(errOut, "features: ") {
		t.Fatalf("not ED-318 = %d %q", code, errOut)
	}
	// The input cap, exceeded by one byte, and met (E-10).
	body := []byte(`{"type":"FeatureCollection","features":[]}`)
	code, _, errOut = convert(t, body, "--to", "ed269", "--max-bytes", strconv.Itoa(len(body)-1))
	if code != exitFailed || !strings.Contains(errOut, "longer than") {
		t.Fatalf("past the cap = %d %q", code, errOut)
	}
	if code, out, errOut := convert(t, body, "--to", "ed269", "--max-bytes", strconv.Itoa(len(body))); code != exitOK || len(out) == 0 {
		t.Fatalf("at the cap = %d %q", code, errOut)
	}
	// A truncated report says how many more there are.
	var b strings.Builder
	b.WriteString(`{"features":[`)
	for i := range 150 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"identifier":"X` + strconv.Itoa(i) + `X12345"}`)
	}
	b.WriteString(`]}`)
	if code, _, errOut := convert(t, []byte(b.String()), "--to", "ed318"); code != exitFailed || !strings.Contains(errOut, "more problems") {
		t.Fatalf("truncated = %d %q", code, errOut[max(0, len(errOut)-200):])
	}
	for _, args := range [][]string{{}, {"--to", "kml"}, {"--to", "ed318", "extra"}, {"--to", "ed318", "--max-bytes", "0"}} {
		if code, _, _ := convert(t, nil, args...); code != exitUsage {
			t.Errorf("%v = %d, want usage", args, code)
		}
	}
	var stderr bytes.Buffer
	if code := runIO(context.Background(), []string{"ed269"}, nil, strings.NewReader(""), &bytes.Buffer{}, &stderr, time.Now()); code != exitUsage {
		t.Errorf("ed269 alone = %d", code)
	}
}
