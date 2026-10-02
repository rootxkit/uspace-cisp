package bus

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// What MessageOf writes, ParseChange reads back; each refusal beside the
// acceptance that differs in one thing (E-01).
func TestParseChange(t *testing.T) {
	c := publication.Change{
		ID: 42, Dataset: publication.DatasetRestrictions, Version: 7, FeatureIDs: []string{"DAR0001"}, RemovedIDs: []string{},
		Reason: publication.ReasonRestrictionActivated, At: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		BBox: &geodesy.BBox{MinLon: 44.7, MinLat: 41.6, MaxLon: 44.9, MaxLat: 41.8},
	}
	raw, err := json.Marshal(MessageOf(c, "https://cisp.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseChange(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 42 || got.Dataset != c.Dataset || got.Version != 7 || got.Reason != c.Reason || !got.At.Equal(c.At) ||
		got.BBox == nil || *got.BBox != *c.BBox || len(got.FeatureIDs) != 1 {
		t.Errorf("parsed %+v", got)
	}
	whole := c
	whole.BBox = nil
	raw2, _ := json.Marshal(MessageOf(whole, "https://cisp.example.test"))
	if got, err := ParseChange(raw2); err != nil || got.BBox != nil {
		t.Errorf("whole dataset: %+v %v", got, err)
	}

	mutate := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f(m)
		out, _ := json.Marshal(m)
		return out
	}
	for name, body := range map[string][]byte{
		"not json":        []byte("{"),
		"unknown member":  mutate(func(m map[string]any) { m["colour"] = "red" }),
		"other schema":    mutate(func(m map[string]any) { m["schema"] = "cis/other/v1" }),
		"msg_id not int":  mutate(func(m map[string]any) { m["msg_id"] = "abc" }),
		"msg_id zero":     mutate(func(m map[string]any) { m["msg_id"] = "0" }),
		"msg_id too long": mutate(func(m map[string]any) { m["msg_id"] = strings.Repeat("9", 20) }),
		"dataset":         mutate(func(m map[string]any) { m["dataset"] = "airports" }),
		"reason":          mutate(func(m map[string]any) { m["reason"] = "subscription_test" }),
		"bbox of three":   mutate(func(m map[string]any) { m["bbox"] = []float64{1, 2, 3} }),
		"too large":       append([]byte(`{"x":"`), append([]byte(strings.Repeat("a", maxChangeMessageBytes)), '"', '}')...),
	} {
		if _, err := ParseChange(body); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConsumerConfig(t *testing.T) {
	jc := ConsumerConfig{}.JetStreamConfig()
	if jc.Durable != "deliver" || jc.AckPolicy != jetstream.AckExplicitPolicy || jc.MaxAckPending != 256 ||
		jc.AckWait != 30*time.Second || jc.MaxDeliver != 20 || jc.FilterSubject != "cis.v1.change.*" ||
		jc.DeliverPolicy != jetstream.DeliverNewPolicy {
		t.Errorf("consumer %+v", jc)
	}
	if jc := (ConsumerConfig{Name: "x", MaxAckPending: 1, AckWait: time.Second, MaxDeliver: 2}).JetStreamConfig(); jc.Durable != "x" || jc.MaxAckPending != 1 || jc.MaxDeliver != 2 {
		t.Errorf("set consumer %+v", jc)
	}
}
