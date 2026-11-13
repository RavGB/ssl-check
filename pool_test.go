package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestForEachBoundsConcurrency(t *testing.T) {
	const n, limit = 40, 4
	var (
		active, peak atomic.Int32
		seen         [n]atomic.Int32
	)
	forEach(context.Background(), n, limit, func(_ context.Context, i int) {
		now := active.Add(1)
		for {
			p := peak.Load()
			if now <= p || peak.CompareAndSwap(p, now) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		seen[i].Add(1)
		active.Add(-1)
	})
	if p := peak.Load(); p > limit {
		t.Errorf("%d ran at once, limit was %d", p, limit)
	}
	if p := peak.Load(); p < 2 {
		t.Errorf("only %d ran at once, the work was not parallel", p)
	}
	for i := range seen {
		if c := seen[i].Load(); c != 1 {
			t.Errorf("index %d ran %d times, want 1", i, c)
		}
	}
}

func TestForEachSkipsWorkAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	forEach(ctx, 10, 2, func(context.Context, int) { calls.Add(1) })
	if c := calls.Load(); c != 0 {
		t.Errorf("%d calls ran after cancel, want 0", c)
	}
}

func TestForEachZeroLimitStillRuns(t *testing.T) {
	var calls atomic.Int32
	forEach(context.Background(), 3, 0, func(context.Context, int) { calls.Add(1) })
	if c := calls.Load(); c != 3 {
		t.Errorf("calls = %d, want 3", c)
	}
}
