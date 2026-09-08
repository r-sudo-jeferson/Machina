package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var ErrOIDCSecretCollision = errors.New("OIDC secret collision")

type OIDCSecrets struct {
	State         string
	Nonce         string
	PKCEVerifier  string
	PKCEChallenge string
}

func NewOIDCSecrets() (OIDCSecrets, error) {
	state, _, err := NewOpaqueToken()
	if err != nil {
		return OIDCSecrets{}, err
	}
	nonce, _, err := NewOpaqueToken()
	if err != nil {
		return OIDCSecrets{}, err
	}
	verifier, _, err := NewOpaqueToken()
	if err != nil {
		return OIDCSecrets{}, err
	}
	if state == nonce || state == verifier || nonce == verifier {
		return OIDCSecrets{}, ErrOIDCSecretCollision
	}

	digest := sha256.Sum256([]byte(verifier))
	return OIDCSecrets{
		State:         state,
		Nonce:         nonce,
		PKCEVerifier:  verifier,
		PKCEChallenge: base64.RawURLEncoding.EncodeToString(digest[:]),
	}, nil
}
