package stream

import (
	"log/slog"
	"net/http"
)

// levelOf is the log level of a refusal: warning for a server-side
// limit (503), info for what a client got wrong.
func levelOf(status int) slog.Level {
	if status >= http.StatusInternalServerError {
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

func attrString(k, v string) slog.Attr      { return slog.String(k, v) }
func attrUint(k string, v uint64) slog.Attr { return slog.Uint64(k, v) }
func attrBool(k string, v bool) slog.Attr   { return slog.Bool(k, v) }
