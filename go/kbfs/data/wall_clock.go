// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package data

import "time"

type WallClock struct {
}

// Now implements the Clock interface for wallClock.
func (wc WallClock) Now() time.Time {
	return time.Now()
}
