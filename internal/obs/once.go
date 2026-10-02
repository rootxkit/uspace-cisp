package obs

import (
	"container/list"
	"sync"
	"time"
)

// DefaultThrottleKeys bounds the keys the package's Once remembers;
// past it the least recently used key is forgotten (E-10), which can
// only let one more line through, never hold one back for ever.
const DefaultThrottleKeys = 1024

// Throttle lets one log line per key through per interval and counts
// the lines it held back, so a refusal path that fires a thousand times
// a second writes one line a period with the count (LESSONS E-09:
// rate-limited, never silenced). It remembers at most MaxKeys keys.
type Throttle struct {
	maxKeys int
	now     func() time.Time

	mu    sync.Mutex
	order *list.List // front: most recently used; values are *throttled
	keys  map[string]*list.Element
}

type throttled struct {
	key        string
	last       time.Time
	suppressed uint64
}

// NewThrottle returns a throttle remembering at most maxKeys keys (0:
// DefaultThrottleKeys) on the clock now (nil: time.Now).
func NewThrottle(maxKeys int, now func() time.Time) *Throttle {
	if maxKeys <= 0 {
		maxKeys = DefaultThrottleKeys
	}
	if now == nil {
		now = time.Now
	}
	return &Throttle{maxKeys: maxKeys, now: now, order: list.New(), keys: map[string]*list.Element{}}
}

// Once reports whether a line for key may be written now: true the
// first time and then at most once per every, with the number of lines
// held back since the last one that went through (to be written with
// it). false means hold this line back; it is counted.
func (t *Throttle) Once(key string, every time.Duration) (ok bool, suppressed uint64) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, found := t.keys[key]; found {
		t.order.MoveToFront(e)
		th, _ := e.Value.(*throttled)
		if now.Sub(th.last) < every {
			th.suppressed++
			return false, 0
		}
		held := th.suppressed
		th.last, th.suppressed = now, 0
		return true, held
	}
	t.keys[key] = t.order.PushFront(&throttled{key: key, last: now})
	for t.order.Len() > t.maxKeys {
		last := t.order.Back()
		old, _ := last.Value.(*throttled)
		t.order.Remove(last)
		delete(t.keys, old.key)
	}
	return true, 0
}

// Len is the number of keys remembered.
func (t *Throttle) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.order.Len()
}

var defaultThrottle = NewThrottle(DefaultThrottleKeys, nil)

// Once is the process-wide Throttle's Once: the rate-limited logging
// helper every refusal path uses. Keys name the path and the reason
// ("stream: origin refused"), never the caller, so the key set stays
// small.
func Once(key string, every time.Duration) (ok bool, suppressed uint64) {
	return defaultThrottle.Once(key, every)
}
