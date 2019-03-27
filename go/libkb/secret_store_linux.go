// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

// +build linux

package libkb

func NewSecretStoreAll(mctx MetaContext) SecretStoreAll {
	g := mctx.G()
	sfile := NewSecretStoreFile(g.Env.GetDataDir())
	sfile.notifyCreate = func(name NormalizedUsername) { notifySecretStoreCreate(g, name) }
	ssecretservice := NewSecretStoreSecretService()
	return NewSecretStoreUpgradeable(ssecretservice, sfile)
}
