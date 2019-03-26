package libkb

import (
	"fmt"

	dbus "github.com/guelfey/go.dbus"
	secsrv "github.com/keybase/go-keychain/secretservice"
)

type SecretStoreSecretService struct {
}

var _ SecretStoreAll = (*SecretStoreSecretService)(nil)

func NewSecretStoreSecretService() *SecretStoreSecretService {
	return &SecretStoreSecretService{}
}

func (s *SecretStoreSecretService) makeAttributes(username NormalizedUsername) secsrv.Attributes {
	return secsrv.Attributes{
		"username": string(username),
		"service":  SecretServiceKeyringServiceName,
	}
}

func (s *SecretStoreSecretService) RetrieveSecret(m MetaContext, username NormalizedUsername) (LKSecFullSecret, error) {
	srv, err := secsrv.NewService()
	if err != nil {
		return LKSecFullSecret{}, err
	}
	session, err := srv.OpenSession(secsrv.AuthenticationPlain)
	if err != nil {
		return LKSecFullSecret{}, err
	}
	items, err := srv.SearchCollection(secsrv.DefaultCollection, s.makeAttributes(username))
	if err != nil {
		return LKSecFullSecret{}, err
	}
	if len(items) < 1 { // and if > 1?
		return LKSecFullSecret{}, fmt.Errorf("no secret found") // need real errtype
	}
	item := items[0]
	err = srv.Unlock([]dbus.ObjectPath{item})
	if err != nil {
		return LKSecFullSecret{}, err
	}
	secret, err := srv.GetSecret(item, session)
	if err != nil {
		return LKSecFullSecret{}, err
	}
	return newLKSecFullSecretFromBytes(secret.Value)
}

func (s *SecretStoreSecretService) StoreSecret(m MetaContext, username NormalizedUsername, secret LKSecFullSecret) error {
	srv, err := secsrv.NewService()
	if err != nil {
		return err
	}
	session, err := srv.OpenSession(secsrv.AuthenticationPlain)
	if err != nil {
		return err
	}
	label := fmt.Sprintf("%s@%s (do not delete)")
	properties := secsrv.NewSecretProperties(label, s.makeAttributes(username))
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

func (s *SecretStoreSecretService) ClearSecret(m MetaContext, username NormalizedUsername) error {
	// noop for "" username? for rest too?
	return nil
}

func (s *SecretStoreSecretService) GetUsersWithStoredSecrets(m MetaContext) ([]string, error) {
	// var usernames []string
	// for k := range s.secrets {
	// 	usernames = append(usernames, k.String())
	// }
	// return usernames, nil
	return nil, nil
}
