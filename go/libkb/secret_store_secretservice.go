// Copyright 2019 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

// +build linux

package libkb

import (
	"fmt"

	dbus "github.com/guelfey/go.dbus"
	secsrv "github.com/keybase/go-keychain/secretservice"

	"github.com/pkg/errors"
)

type SecretStoreSecretService struct{}

var _ SecretStoreAll = (*SecretStoreSecretService)(nil)

func NewSecretStoreSecretService() *SecretStoreSecretService {
	return &SecretStoreSecretService{}
}

func (s *SecretStoreSecretService) makeServiceAttributes(mctx MetaContext) secsrv.Attributes {
	return secsrv.Attributes{
		"service": mctx.G().Env.GetStoredSecretServiceName(),
	}
}

// TODO add note about do not delete if NOPW?
// "note": "This is a "
func (s *SecretStoreSecretService) makeAttributes(mctx MetaContext, username NormalizedUsername) secsrv.Attributes {
	serviceAttributes := s.makeServiceAttributes(mctx)
	serviceAttributes["username"] = string(username)
	return serviceAttributes
}

func (s *SecretStoreSecretService) retrieveSingleItem(mctx MetaContext, srv *secsrv.SecretService, username NormalizedUsername) (dbus.ObjectPath, error) {
	if srv == nil {
		return "", fmt.Errorf("got nil d-bus secretservice")
	}
	items, err := srv.SearchCollection(secsrv.DefaultCollection, s.makeAttributes(mctx, username))
	if err != nil {
		return "", err
	}
	if len(items) < 1 { // and if > 1? clear all..or something
		return "", fmt.Errorf("no secret found") // need real errtype
	}
	item := items[0]
	err = srv.Unlock([]dbus.ObjectPath{item})
	if err != nil {
		return "", err
	}
	return item, nil
}

func (s *SecretStoreSecretService) RetrieveSecret(mctx MetaContext, username NormalizedUsername) (LKSecFullSecret, error) {
	srv, err := secsrv.NewService()
	if err != nil {
		return LKSecFullSecret{}, err
	}
	session, err := srv.OpenSession(secsrv.AuthenticationPlain)
	if err != nil {
		return LKSecFullSecret{}, err
	}

	item, err := s.retrieveSingleItem(mctx, srv, username)
	if err != nil {
		return LKSecFullSecret{}, err
	}

	secret, err := srv.GetSecret(item, session)
	if err != nil {
		return LKSecFullSecret{}, err
	}
	return newLKSecFullSecretFromBytes(secret.Value)
}

func (s *SecretStoreSecretService) StoreSecret(mctx MetaContext, username NormalizedUsername, secret LKSecFullSecret) error {
	srv, err := secsrv.NewService()
	if err != nil {
		return err
	}
	session, err := srv.OpenSession(secsrv.AuthenticationPlain)
	if err != nil {
		return err
	}
	label := fmt.Sprintf("%s@%s", username, mctx.G().Env.GetStoredSecretServiceName())
	properties := secsrv.NewSecretProperties(label, s.makeAttributes(mctx, username))
	srvSecret := secsrv.Secret{
		Session:     session,
		Parameters:  nil,
		Value:       secret.Bytes(),
		ContentType: "application/octet-stream",
	}
	err = srv.Unlock([]dbus.ObjectPath{secsrv.DefaultCollection})
	if err != nil {
		return err
	}
	_, err = srv.CreateItem(secsrv.DefaultCollection, properties, srvSecret, true /* replace existing secret */)
	if err != nil {
		return err
	}

	return nil
}

func (s *SecretStoreSecretService) ClearSecret(mctx MetaContext, username NormalizedUsername) error {
	srv, err := secsrv.NewService()
	if err != nil {
		return err
	}
	item, err := s.retrieveSingleItem(mctx, srv, username)
	if err != nil {
		return err
	}
	err = srv.DeleteItem(item)
	if err != nil {
		return err
	}
	return nil
}

func (s *SecretStoreSecretService) GetUsersWithStoredSecrets(mctx MetaContext) ([]string, error) {
	srv, err := secsrv.NewService()
	if err != nil {
		return nil, err
	}
	items, err := srv.SearchCollection(secsrv.DefaultCollection, s.makeServiceAttributes(mctx))
	if err != nil {
		return nil, err
	}
	var usernames []string
	for _, item := range items {
		attributes, err := srv.GetAttributes(item)
		if err != nil {
			return nil, err
		}
		username, ok := attributes["username"]
		if !ok {
			return nil, errors.New("secret does not have username key")
		}
		usernames = append(usernames, username)
	}
	return usernames, nil
}
