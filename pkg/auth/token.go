package auth

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

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

func GenerateToken(edSecretKey []byte, request *Request) (string, error) {
	if request == nil {
		return "", errors.New("request cannot be nil")
	}

	if len(request.PublicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid public key length")
	}

	message := crypto.ConcatBytes(
		[]byte("ephmrl-auth:v2:ed25519"),
		[]byte(request.Method),
		[]byte(request.Path),
		[]byte(request.Type),
		[]byte(request.BodyHash),
		fmt.Appendf([]byte{}, "%d", request.Timestamp),
		[]byte(request.UUID),
		[]byte(base64.StdEncoding.EncodeToString(request.PublicKey)),
	)

	signature, err := crypto.SignEd25519(edSecretKey, message)
	if err != nil {
		return "", err
	}

	timestampBinary := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBinary, uint64(request.Timestamp))

	id, _ := uuid.Parse(request.UUID)

	rawToken := make([]byte, 0, 120)
	rawToken = append(rawToken, id[:]...)
	rawToken = append(rawToken, request.PublicKey...)
	rawToken = append(rawToken, signature...)
	rawToken = append(rawToken, timestampBinary...)

	token := base64.StdEncoding.EncodeToString(rawToken)

	return token, nil
}

func DecodeToken(token string, request *Request) (uuid.UUID, []byte, []byte, int64, error) {
	if len(token) == 160 {
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
