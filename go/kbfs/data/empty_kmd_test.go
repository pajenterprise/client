// Copyright 2019 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package data

import (
	"context"

	"github.com/keybase/client/go/kbfs/idutil"
	"github.com/keybase/client/go/kbfs/kbfscodec"
	"github.com/keybase/client/go/kbfs/kbfscrypto"
	"github.com/keybase/client/go/kbfs/kbfsmd"
	"github.com/keybase/client/go/kbfs/libkey"
	"github.com/keybase/client/go/kbfs/tlf"
	"github.com/keybase/client/go/kbfs/tlfhandle"
	"github.com/keybase/client/go/protocol/keybase1"
)

type emptyKeyMetadata struct {
	tlfID  tlf.ID
	keyGen kbfsmd.KeyGen
}

var _ libkey.KeyMetadata = emptyKeyMetadata{}

func (kmd emptyKeyMetadata) TlfID() tlf.ID {
	return kmd.tlfID
}

func (kmd emptyKeyMetadata) TypeForKeying() tlf.KeyingType {
	return kmd.TlfID().Type().ToKeyingType()
}

// GetTlfHandle just returns nil. This contradicts the requirements
// for KeyMetadata, but emptyKeyMetadata shouldn't be used in contexts
// that actually use GetTlfHandle().
func (kmd emptyKeyMetadata) GetTlfHandle() *tlfhandle.Handle {
	return nil
}

func (kmd emptyKeyMetadata) IsWriter(
	_ context.Context, _ kbfsmd.TeamMembershipChecker, _ idutil.OfflineStatusGetter,
	_ keybase1.UID, _ kbfscrypto.VerifyingKey) (bool, error) {
	return false, nil
}

func (kmd emptyKeyMetadata) LatestKeyGeneration() kbfsmd.KeyGen {
	return kmd.keyGen
}

func (kmd emptyKeyMetadata) HasKeyForUser(user keybase1.UID) (bool, error) {
	return false, nil
}

func (kmd emptyKeyMetadata) GetTLFCryptKeyParams(
	keyGen kbfsmd.KeyGen, user keybase1.UID, key kbfscrypto.CryptPublicKey) (
	kbfscrypto.TLFEphemeralPublicKey, kbfscrypto.EncryptedTLFCryptKeyClientHalf,
	kbfscrypto.TLFCryptKeyServerHalfID, bool, error) {
	return kbfscrypto.TLFEphemeralPublicKey{},
		kbfscrypto.EncryptedTLFCryptKeyClientHalf{},
		kbfscrypto.TLFCryptKeyServerHalfID{}, false, nil
}

func (kmd emptyKeyMetadata) StoresHistoricTLFCryptKeys() bool {
	return false
}

func (kmd emptyKeyMetadata) GetHistoricTLFCryptKey(
	codec kbfscodec.Codec, keyGen kbfsmd.KeyGen, key kbfscrypto.TLFCryptKey) (
	kbfscrypto.TLFCryptKey, error) {
	return kbfscrypto.TLFCryptKey{}, nil
}
