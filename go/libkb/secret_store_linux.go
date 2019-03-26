// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

// +build linux

package libkb

func NewSecretStoreAll(mctx MetaContext) SecretStoreAll {
	s := NewSecretStoreSecretService()
	return s
}
