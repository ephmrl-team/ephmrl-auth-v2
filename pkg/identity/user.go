package identity

import (
	"errors"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/ephmrl-team/ephmrl-auth-v2/internal/crypto"
	"github.com/vmihailenco/msgpack/v5"
)

type PublicKeys struct {
	Ed25519 []byte `json:"ed25519_public_key"`
}

type SecretKeys struct {
	Ed25519 []byte
}

type Identity struct {
	PublicKeys PublicKeys `json:"public_keys"`
}

func (s *SecretKeys) Wipe() {
	if s == nil {
		return
	}

	crypto.Zero(s.Ed25519)
}

func (s *SecretKeys) Pack() ([]byte, error) {
	return msgpack.Marshal(s)
}

func Unpack(packed []byte) (*SecretKeys, error) {
	var s SecretKeys
	err := msgpack.Unmarshal(packed, &s)
	return &s, err
}

func Generate() (*Identity, *SecretKeys, error) {
	var err error

	var ed25519Secret []byte

	defer func() {
		if err != nil {
			crypto.Zero(ed25519Secret)
		}
	}()

	var ed25519Public []byte
	ed25519Public, ed25519Secret, err = crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	identity := &Identity{
		PublicKeys: PublicKeys{
			Ed25519: ed25519Public,
		},
	}

	secret := &SecretKeys{
		Ed25519: ed25519Secret,
	}

	return identity, secret, nil
}

func NewSecretKeys(ed []byte) (secret *SecretKeys, err error) {
	if len(ed) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 secret key size: must be exactly 32 bytes")
	}

	var edCopy []byte

	defer func() {
		if err != nil {
			crypto.Zero(edCopy)
		}
	}()

	edCopy = make([]byte, len(ed))
	copy(edCopy, ed)

	secret = &SecretKeys{
		Ed25519: edCopy,
	}

	return secret, nil
}
