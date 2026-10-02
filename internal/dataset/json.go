package dataset

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// member is one member of a JSON object, its value as published.
type member struct {
	key   string
	value json.RawMessage
}

var (
	errNotObject = errors.New("is not a JSON object")
	errNotArray  = errors.New("is not a JSON array")
)

// repeatedError names a member that appears twice in one object.
type repeatedError struct{ key string }

func (e *repeatedError) Error() string { return "repeats the member " + quote(e.key) }

// members reads a JSON object into its members in document order. It
// refuses anything but one object, and an object that repeats a member
// (*repeatedError): a repeated member is ambiguous, and the CISP never
// picks one.
func members(raw []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, errNotObject
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errNotObject
	}
	var out []member
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errNotObject
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errNotObject
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errNotObject
		}
		if seen[key] {
			return nil, &repeatedError{key: key}
		}
		seen[key] = true
		out = append(out, member{key: key, value: v})
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, errNotObject
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errNotObject
	}
	return out, nil
}

// elements reads a JSON array into its elements, as published.
func elements(raw []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errNotArray
	}
	var out []json.RawMessage
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, errNotArray
	}
	return out, nil
}

// stringValue is raw as a JSON string, and false for anything else.
func stringValue(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return "", false
	}
	return s, true
}

// numberValue is raw as a finite JSON number, and false for anything else.
func numberValue(raw json.RawMessage) (float64, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || (trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9')) {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(trimmed), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, false
	}
	return f, true
}

// isObject reports whether raw is a JSON object (its members unread).
func isObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// describe is the JSON kind of raw, for a refusal.
func describe(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "nothing"
	}
	switch trimmed[0] {
	case '{':
		return "an object"
	case '[':
		return "an array"
	case '"':
		return "a string"
	case 't', 'f':
		return "a boolean"
	case 'n':
		return "null"
	}
	return "a number"
}

// maxQuoted bounds a value repeated in a refusal.
const maxQuoted = 64

// quote is s quoted for a refusal, cut at maxQuoted characters.
func quote(s string) string {
	if utf8.RuneCountInString(s) > maxQuoted {
		r := []rune(s)
		s = string(r[:maxQuoted]) + "..."
	}
	return strconv.Quote(s)
}

func join(parent, key string) string { return parent + "." + key }

func index(parent string, i int) string { return parent + "[" + strconv.Itoa(i) + "]" }
