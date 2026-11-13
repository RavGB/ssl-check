package main

import (
	"context"
	"sync"
)

// forEach calls fn once for every index from 0 to n-1. Each call runs in its
// own goroutine, and a semaphore keeps at most limit of them working at the
// same time. It returns when every call has finished. Indexes that have not
// started when ctx is cancelled are skipped.
func forEach(ctx context.Context, n, limit int, fn func(ctx context.Context, i int)) {
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			fn(ctx, i)
		})
	}
	wg.Wait()
}
