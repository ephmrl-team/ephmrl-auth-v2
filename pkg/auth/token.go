package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/ephmrl-team/ephmrl-auth-v2/internal/crypto"
	"github.com/google/uuid"
)

type Request struct {
	Method    string
	Path      string
	Type      string
	BodyHash  string
	Timestamp int64
	UUID      string
	PublicKey []byte
}

func NewRequest(method, path, requestType, bodyHash string, publicKey []byte) (*Request, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().Unix()

	request := &Request{
		Method:    method,
		Path:      path,
		Type:      requestType,
		BodyHash:  bodyHash,
		Timestamp: timestamp,
		UUID:      uuid.String(),
		PublicKey: publicKey,
	}

	return request, nil
}

func GenerateToken(edSecretKey []byte, request *Request) (string, error) {
	if request == nil {
		return "", errors.New("request cannot be nil")
	}

	id, err := uuid.Parse(request.UUID)
	if err != nil || id == uuid.Nil || id.Version() != 4 {
		return "", errors.New("invalid uuid")
	}

	if len(edSecretKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid secret key length")
	}

	if len(request.PublicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid public key length")
	}

	if derivedPublicKey := ed25519.PrivateKey(edSecretKey).Public().(ed25519.PublicKey); !bytes.Equal(request.PublicKey, derivedPublicKey[:]) {
		return "", errors.New("key pair mismatch")
	}

	message := crypto.ConcatBytes(
		[]byte("ephmrl-auth:v2:ed25519"),
		[]byte(request.Method),
		[]byte(request.Path),
		[]byte(request.Type),
		[]byte(request.BodyHash),
		fmt.Appendf([]byte{}, "%d", request.Timestamp),
		[]byte(id.String()),
		[]byte(base64.StdEncoding.EncodeToString(request.PublicKey)),
	)

	signature, err := crypto.SignEd25519(edSecretKey, message)
	if err != nil {
		return "", err
	}

	timestampBinary := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBinary, uint64(request.Timestamp))

	rawToken := make([]byte, 0, 120)
	rawToken = append(rawToken, id[:]...)
	rawToken = append(rawToken, request.PublicKey...)
	rawToken = append(rawToken, signature...)
	rawToken = append(rawToken, timestampBinary...)

	token := base64.StdEncoding.EncodeToString(rawToken)

	return token, nil
}

func DecodeToken(token string, request *Request) (uuid.UUID, []byte, []byte, int64, error) {
	if request == nil {
		return uuid.Nil, nil, nil, 0, errors.New("request cannot be nil")
	}

	if len(token) != 160 {
		return uuid.Nil, nil, nil, 0, errors.New("invalid token length")
	}

	rawToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return uuid.Nil, nil, nil, 0, err
	}

	if len(rawToken) != 120 {
		return uuid.Nil, nil, nil, 0, errors.New("invalid token length")
	}

	parsedUUID, err := uuid.FromBytes(rawToken[0:16])
	if err != nil {
		return uuid.Nil, nil, nil, 0, err
	}

	pc := rawToken[16:48]

	if err := crypto.ValidatePublicKeyStrict(pc); err != nil {
		return uuid.Nil, nil, nil, 0, err
	}

	signature := rawToken[48:112]
	timestamp := int64(binary.BigEndian.Uint64(rawToken[112:120]))

	message := crypto.ConcatBytes(
		[]byte("ephmrl-auth:v2:ed25519"),
		[]byte(request.Method),
		[]byte(request.Path),
		[]byte(request.Type),
		[]byte(request.BodyHash),
		fmt.Appendf([]byte{}, "%d", timestamp),
		[]byte(parsedUUID.String()),
		[]byte(base64.StdEncoding.EncodeToString(pc)),
	)

	isValid, err := crypto.VerifyEd25519(pc, message, signature)
	if err != nil {
		return uuid.UUID{}, nil, nil, 0, err
	}

	if !isValid {
		return uuid.UUID{}, nil, nil, 0, errors.New("invalid signature")
	}

	return parsedUUID, pc, signature, timestamp, nil
}
