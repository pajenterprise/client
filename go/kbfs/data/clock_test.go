// Copyright 2019 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package data

import (
	"sync"
	"time"
)

// TestClock returns a set time as the current time.
type TestClock struct {
	l sync.Mutex
	t time.Time
}

func newTestClockNow() *TestClock {
	return &TestClock{t: time.Now()}
}

func newTestClockAndTimeNow() (*TestClock, time.Time) {
	t0 := time.Now()
	return &TestClock{t: t0}, t0
}

// Now implements the Clock interface for TestClock.
func (tc *TestClock) Now() time.Time {
	tc.l.Lock()
	defer tc.l.Unlock()
	return tc.t
}

// Set sets the test clock time.
func (tc *TestClock) Set(t time.Time) {
	tc.l.Lock()
	defer tc.l.Unlock()
	tc.t = t
}

// Add adds to the test clock time.
func (tc *TestClock) Add(d time.Duration) {
	tc.l.Lock()
	defer tc.l.Unlock()
	tc.t = tc.t.Add(d)
}
