package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/ed25519"
)

func GenerateEd25519KeyPair() ([]byte, []byte, error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkOut := make([]byte, ed25519.PublicKeySize)
	skOut := make([]byte, ed25519.PrivateKeySize)
	copy(pkOut, pk)
	copy(skOut, sk)

	defer func() {
		Zero(sk)
	}()

	return pkOut, skOut, nil
}

func SignEd25519(skBytes []byte, message []byte) ([]byte, error) {
	if len(skBytes) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key size: must be exactly 64 bytes")
	}

	sk := make(ed25519.PrivateKey, len(skBytes))
	copy(sk, skBytes)

	defer func() {
		Zero(sk)
	}()

	var signature []byte
	var signErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				signErr = fmt.Errorf("signing panic: %v", r)
			}
		}()
		signature = ed25519.Sign(sk, message)
	}()

	if signErr != nil {
		return nil, signErr
	}

	sigOut := make([]byte, len(signature))
	copy(sigOut, signature)

	return sigOut, nil
}

func VerifyEd25519(pkBytes []byte, message []byte, signature []byte) (bool, error) {
	if len(pkBytes) != ed25519.PublicKeySize {
		return false, errors.New("invalid public key size: must be exactly 32 bytes")
	}
	if len(signature) != ed25519.SignatureSize {
		return false, errors.New("invalid signature size: must be exactly 64 bytes")
	}

	pk := ed25519.PublicKey(pkBytes)
	var ok bool
	var verifyErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				verifyErr = fmt.Errorf("verification panic: %v", r)
			}
		}()
		ok = ed25519.Verify(pk, message, signature)
	}()

	if verifyErr != nil {
		return false, verifyErr
	}

	return ok, nil
}
