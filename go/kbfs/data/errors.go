// Copyright 2019 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package data

import "fmt"

// NameExistsError indicates that the user tried to create an entry
// for a name that already existed in a subdirectory.
type NameExistsError struct {
	Name string
}

// Error implements the error interface for NameExistsError
func (e NameExistsError) Error() string {
	return fmt.Sprintf("%s already exists", e.Name)
}

// BadSplitError indicates that the BlockSplitter has an error.
type BadSplitError struct {
}

// Error implements the error interface for BadSplitError
func (e BadSplitError) Error() string {
	return "Unexpected bad block split"
}
