package stream

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// truncateOrigin never splits a UTF-8 sequence (N4): an Origin of multi-byte
// runes cut at 128 bytes stays valid UTF-8 and at most 128 bytes; a
// short or ASCII one is unchanged or cut exactly (E-01).
func TestTruncateKeepsRunesWhole(t *testing.T) {
	long := "https://x" + strings.Repeat("ქ", 100) // 3 bytes each; 128 falls inside one
	got := truncateOrigin(long)
	if !utf8.ValidString(got) || len(got) > 128 || !strings.HasPrefix(long, got) || len(got) < 126 {
		t.Errorf("cut %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	if got := truncateOrigin(strings.Repeat("a", 200)); got != strings.Repeat("a", 128) {
		t.Errorf("ASCII cut to %d", len(got))
	}
	if got := truncateOrigin("https://ok.ge"); got != "https://ok.ge" {
		t.Errorf("short %q", got)
	}
}
