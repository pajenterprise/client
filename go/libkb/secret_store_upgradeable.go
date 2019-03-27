package libkb

type SecretStoreUpgradeable struct {
	a SecretStoreAll
	b SecretStoreAll
}

var _ SecretStoreAll = (*SecretStoreUpgradeable)(nil)

func NewSecretStoreUpgradeable(a, b SecretStoreAll) *SecretStoreUpgradeable {
	return &SecretStoreUpgradeable{a: a, b: b}
}

func (s *SecretStoreUpgradeable) RetrieveSecret(mctx MetaContext, username NormalizedUsername) (LKSecFullSecret, error) {
	secret, err1 := s.a.RetrieveSecret(mctx, username)
	if err1 == nil {
		return secret, nil
	}
	secret, err2 := s.b.RetrieveSecret(mctx, username)
	if err2 == nil {
		storeAErr := s.a.StoreSecret(mctx, username, secret)
		if storeAErr == nil {
			mctx.Debug("Upgraded secret for %s to secretstore a", username)
		} else {
			mctx.Debug("Failed to upgrade secret for %s to secretstore a: %s", username, storeAErr)
		}
		return secret, nil
	}
	return LKSecFullSecret{}, CombineErrors(err1, err2)
}

func (s *SecretStoreUpgradeable) StoreSecret(mctx MetaContext, username NormalizedUsername, secret LKSecFullSecret) error {
	err1 := s.a.StoreSecret(mctx, username, secret)
	if err1 == nil {
		clearBErr := s.b.ClearSecret(mctx, username)
		if clearBErr == nil {
			mctx.Debug("Cleared secret for %s from secretstore b", username)
		} else {
			mctx.Debug("Failed to clear secret for %s from secretstore b: %s", username, clearBErr)
		}
		return nil
	}

	err2 := s.b.StoreSecret(mctx, username, secret)
	if err2 == nil {
		return nil
	}
	return CombineErrors(err1, err2)
}

func (s *SecretStoreUpgradeable) ClearSecret(mctx MetaContext, username NormalizedUsername) error {
	err1 := s.a.ClearSecret(mctx, username)
	err2 := s.b.ClearSecret(mctx, username)
	return CombineErrors(err1, err2)
}

func (s *SecretStoreUpgradeable) GetUsersWithStoredSecrets(mctx MetaContext) ([]string, error) {
	usernames := make(map[string]bool)
	usernamesA, err1 := s.a.GetUsersWithStoredSecrets(mctx)
	if err1 == nil {
		for _, u := range usernamesA {
			usernames[u] = true
		}
	}
	usernamesB, err2 := s.b.GetUsersWithStoredSecrets(mctx)
	if err2 == nil {
		for _, u := range usernamesB {
			usernames[u] = true
		}
	}
	var usernamesList []string
	for username := range usernames {
		usernamesList = append(usernamesList, username)
	}
	return usernamesList, CombineErrors(err1, err2)
}
