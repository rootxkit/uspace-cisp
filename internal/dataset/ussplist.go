package dataset

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/ed269"
	"github.com/rootxkit/uspace-core/ed318"
)

// UsspListSchema is the schema member of a USSP list.
const UsspListSchema = "cis/ussp_list/v1"

// Bounds of cis/ussp_list/v1 (E-10); api/openapi.yaml UsspList states
// the same.
const (
	MaxUssps                    = 200
	MaxUsspIDChars              = 64
	MaxUsspNameChars            = 200
	MaxCertificateIDChars       = 64
	MaxURLChars                 = 2048
	MaxHostChars                = 253
	MaxEmailChars               = 254
	MaxPhoneChars               = 50
	MaxLimitations              = 50
	MaxLimitationChars          = 1000
	minEmailChars               = 3
	usspListServedOnlyMemberTag = "cis_"
)

// The Annex VI U-space service names a USSP may be certified for.
var annexVIServices = []string{
	"network_identification", "geo_awareness", "flight_authorisation",
	"traffic_information", "weather", "conformance_monitoring",
}

// The USSP statuses.
var usspStatuses = []string{"operating", "suspended", "limited"}

var (
	listMembers    = []string{"schema", "issued", "ussps"}
	usspMembers    = []string{"ussp_id", "name", "contact", "certificate_id", "base_url", "services", "certification_limitations", "valid_from", "valid_until", "terms_url", "status"}
	contactMembers = []string{"email", "phone", "url"}
)

// UsspList is an accepted cis/ussp_list/v1 document.
type UsspList struct {
	Schema string
	Issued time.Time
	Ussps  []Ussp
}

// Ussp is one entry of the list.
type Ussp struct {
	UsspID                   string
	Name                     string
	Contact                  UsspContact
	CertificateID            string
	BaseURL                  string
	Services                 []string
	CertificationLimitations []string
	ValidFrom, ValidUntil    time.Time
	TermsURL                 string
	Status                   string
}

// UsspContact is a USSP's contact; every member is optional.
type UsspContact struct {
	Email, Phone, URL *string
}

// usspListRules validate cis/ussp_list/v1 by hand, bounded (docs/PLAN.md
// section 4 rejects a schema library at run time).
type usspListRules struct{}

// Validate accepts the list whole or refuses it with every problem.
func (usspListRules) Validate(body []byte, lim ed318.Limits, _ time.Time) (Accepted, *ed269.Problems) {
	c := newCollector(lim)
	list := validateUsspList(body, c)
	if p := c.result(); p != nil {
		return Accepted{}, p
	}
	return Accepted{UsspList: list}, nil
}

// ValidateUsspList validates body as cis/ussp_list/v1 with the default
// problem cap; the fuzz target and the schema examples use it.
func ValidateUsspList(body []byte) (*UsspList, *ed269.Problems) {
	acc, probs := usspListRules{}.Validate(body, ed318.Limits{}, time.Time{})
	return acc.UsspList, probs
}

func validateUsspList(body []byte, c *collector) *UsspList {
	if !utf8.Valid(body) {
		c.add("$", "not UTF-8")
		return nil
	}
	ms, err := members(body)
	if err != nil {
		c.add("$", objectRefusal(err, "the document", body))
		return nil
	}
	list := &UsspList{}
	got := map[string]json.RawMessage{}
	for _, m := range ms {
		switch {
		case strings.HasPrefix(m.key, usspListServedOnlyMemberTag):
			c.add(m.key, "is written by the CISP when it serves the list; a publication may not carry it")
		case !slices.Contains(listMembers, m.key):
			c.add(m.key, "unknown member of "+UsspListSchema+" (a closed schema)")
		default:
			got[m.key] = m.value
		}
	}
	for _, name := range listMembers {
		if _, ok := got[name]; !ok {
			c.add(name, "is required")
		}
	}
	if raw, ok := got["schema"]; ok {
		if s, ok := stringValue(raw); !ok || s != UsspListSchema {
			c.add("schema", "must be "+quote(UsspListSchema))
		} else {
			list.Schema = s
		}
	}
	if raw, ok := got["issued"]; ok {
		list.Issued, _ = timeValue(raw, "issued", c)
	}
	if raw, ok := got["ussps"]; ok {
		list.Ussps = validateUssps(raw, c)
	}
	return list
}

func validateUssps(raw json.RawMessage, c *collector) []Ussp {
	entries, err := elements(raw)
	if err != nil {
		c.add("ussps", "must be an array, not "+describe(raw))
		return nil
	}
	if len(entries) > MaxUssps {
		c.add("ussps", "has "+itoa(len(entries))+" entries; at most "+itoa(MaxUssps))
		return nil
	}
	out := make([]Ussp, 0, len(entries))
	ids := map[string]int{}
	for i, e := range entries {
		where := index("ussps", i)
		u := validateUssp(e, where, c)
		if u.UsspID != "" {
			if first, dup := ids[u.UsspID]; dup {
				c.add(join(where, "ussp_id"), quote(u.UsspID)+" repeats "+join(index("ussps", first), "ussp_id")+"; ussp_id is unique in the list")
			} else {
				ids[u.UsspID] = i
			}
		}
		out = append(out, u)
	}
	return out
}

func validateUssp(raw json.RawMessage, where string, c *collector) Ussp {
	var u Ussp
	ms, err := members(raw)
	if err != nil {
		c.add(where, objectRefusal(err, "a USSP entry", raw))
		return u
	}
	got := map[string]json.RawMessage{}
	for _, m := range ms {
		if !slices.Contains(usspMembers, m.key) {
			c.add(join(where, m.key), "unknown member of a USSP entry (a closed schema)")
			continue
		}
		got[m.key] = m.value
	}
	for _, name := range usspMembers {
		if _, ok := got[name]; !ok {
			c.add(join(where, name), "is required")
		}
	}
	str := func(name string, maxChars int) string {
		raw, ok := got[name]
		if !ok {
			return ""
		}
		s, _ := boundedString(raw, join(where, name), 1, maxChars, c)
		return s
	}
	u.UsspID = str("ussp_id", MaxUsspIDChars)
	u.Name = str("name", MaxUsspNameChars)
	u.CertificateID = str("certificate_id", MaxCertificateIDChars)
	if raw, ok := got["base_url"]; ok {
		u.BaseURL = httpsURL(raw, join(where, "base_url"), c)
	}
	if raw, ok := got["terms_url"]; ok {
		u.TermsURL = httpsURL(raw, join(where, "terms_url"), c)
	}
	if raw, ok := got["contact"]; ok {
		u.Contact = validateContact(raw, join(where, "contact"), c)
	}
	if raw, ok := got["services"]; ok {
		u.Services = enumList(raw, join(where, "services"), annexVIServices, len(annexVIServices), c)
	}
	if raw, ok := got["certification_limitations"]; ok {
		u.CertificationLimitations = stringList(raw, join(where, "certification_limitations"), MaxLimitations, MaxLimitationChars, c)
	}
	var fromOK, untilOK bool
	if raw, ok := got["valid_from"]; ok {
		u.ValidFrom, fromOK = timeValue(raw, join(where, "valid_from"), c)
	}
	if raw, ok := got["valid_until"]; ok {
		u.ValidUntil, untilOK = timeValue(raw, join(where, "valid_until"), c)
	}
	if fromOK && untilOK && u.ValidUntil.Before(u.ValidFrom) {
		c.add(join(where, "valid_until"), "is before valid_from")
	}
	if raw, ok := got["status"]; ok {
		s, ok := stringValue(raw)
		if !ok || !slices.Contains(usspStatuses, s) {
			c.add(join(where, "status"), "must be one of "+strings.Join(usspStatuses, ", "))
		} else {
			u.Status = s
		}
	}
	return u
}

func validateContact(raw json.RawMessage, where string, c *collector) UsspContact {
	var out UsspContact
	ms, err := members(raw)
	if err != nil {
		c.add(where, objectRefusal(err, "the contact", raw))
		return out
	}
	for _, m := range ms {
		here := join(where, m.key)
		switch m.key {
		case "email":
			if s, ok := boundedString(m.value, here, minEmailChars, MaxEmailChars, c); ok {
				if !strings.Contains(s, "@") {
					c.add(here, "is not an e-mail address")
				} else {
					out.Email = &s
				}
			}
		case "phone":
			if s, ok := boundedString(m.value, here, 1, MaxPhoneChars, c); ok {
				out.Phone = &s
			}
		case "url":
			if s := httpsURL(m.value, here, c); s != "" {
				out.URL = &s
			}
		default:
			c.add(here, "unknown member of the contact; it holds "+strings.Join(contactMembers, ", "))
		}
	}
	return out
}

// objectRefusal is the reason for a value that is not one object.
func objectRefusal(err error, what string, raw json.RawMessage) string {
	if r, ok := asRepeated(err); ok {
		return r.Error()
	}
	return what + " must be a JSON object, not " + describe(raw)
}

func asRepeated(err error) (*repeatedError, bool) {
	var r *repeatedError
	ok := errors.As(err, &r)
	return r, ok
}

// boundedString is raw as a string of minChars to maxChars characters.
func boundedString(raw json.RawMessage, where string, minChars, maxChars int, c *collector) (string, bool) {
	s, ok := stringValue(raw)
	if !ok {
		c.add(where, "must be a string, not "+describe(raw))
		return "", false
	}
	n := utf8.RuneCountInString(s)
	switch {
	case n < minChars:
		c.add(where, "has "+itoa(n)+" characters; at least "+itoa(minChars))
		return "", false
	case n > maxChars:
		c.add(where, "has "+itoa(n)+" characters; at most "+itoa(maxChars))
		return "", false
	}
	return s, true
}

// httpsURL is raw as an absolute https URL with a host of at most
// MaxHostChars characters and no userinfo, or "" after a refusal.
func httpsURL(raw json.RawMessage, where string, c *collector) string {
	s, ok := boundedString(raw, where, 1, MaxURLChars, c)
	if !ok {
		return ""
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		c.add(where, "is not a URL")
	case u.Scheme != "https":
		c.add(where, "must be an https URL")
	case u.User != nil:
		c.add(where, "must not carry userinfo (a name or password before the host)")
	case u.Opaque != "" || u.Hostname() == "":
		c.add(where, "has no host")
	case len(u.Hostname()) > MaxHostChars:
		c.add(where, "has a host of "+itoa(len(u.Hostname()))+" characters; at most "+itoa(MaxHostChars))
	default:
		return s
	}
	return ""
}

// enumList is raw as an array of up to maxItems values from allowed.
func enumList(raw json.RawMessage, where string, allowed []string, maxItems int, c *collector) []string {
	list, err := elements(raw)
	if err != nil {
		c.add(where, "must be an array, not "+describe(raw))
		return nil
	}
	if len(list) > maxItems {
		c.add(where, "has "+itoa(len(list))+" entries; at most "+itoa(maxItems))
		return nil
	}
	out := make([]string, 0, len(list))
	for k, e := range list {
		s, ok := stringValue(e)
		if !ok || !slices.Contains(allowed, s) {
			c.add(index(where, k), "must be one of "+strings.Join(allowed, ", "))
			continue
		}
		out = append(out, s)
	}
	return out
}

// stringList is raw as an array of up to maxItems strings of at most
// maxChars characters.
func stringList(raw json.RawMessage, where string, maxItems, maxChars int, c *collector) []string {
	list, err := elements(raw)
	if err != nil {
		c.add(where, "must be an array, not "+describe(raw))
		return nil
	}
	if len(list) > maxItems {
		c.add(where, "has "+itoa(len(list))+" entries; at most "+itoa(maxItems))
		return nil
	}
	out := make([]string, 0, len(list))
	for k, e := range list {
		if s, ok := boundedString(e, index(where, k), 0, maxChars, c); ok {
			out = append(out, s)
		}
	}
	return out
}

// timeValue is raw as an RFC 3339 date-time with an offset.
func timeValue(raw json.RawMessage, where string, c *collector) (time.Time, bool) {
	s, ok := stringValue(raw)
	if !ok {
		c.add(where, "must be an RFC 3339 date-time string, not "+describe(raw))
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		c.add(where, quote(s)+" is not an RFC 3339 date-time with an offset")
		return time.Time{}, false
	}
	return t, true
}

func itoa(n int) string { return strconv.Itoa(n) }
