package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

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
	PublicKey string
}

func GenerateToken(edPublicKey, edSecretKey []byte, request *Request) string {
	uuid, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}

	message := crypto.ConcatBytes(
		[]byte(request.Method),
		[]byte(request.Path),
		[]byte(request.Type),
		[]byte(request.BodyHash),
		fmt.Appendf([]byte{}, "%d", request.Timestamp),
		[]byte(uuid.String()),
		[]byte(base64.StdEncoding.EncodeToString(edPublicKey)),
	)

	signature := ed25519.Sign(edSecretKey, message)

	timestampBinary := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBinary, uint64(request.Timestamp))

	rawToken := make([]byte, 0, 120)
	rawToken = append(rawToken, uuid[:]...)
	rawToken = append(rawToken, edPublicKey...)
	rawToken = append(rawToken, signature...)
	rawToken = append(rawToken, timestampBinary...)

	token := base64.StdEncoding.EncodeToString(rawToken)

	return token
}

func DecodeToken(token string, request *Request) (uuid.UUID, []byte, []byte, int64, error) {
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
		[]byte(request.Method),
		[]byte(request.Path),
		[]byte(request.Type),
		[]byte(request.BodyHash),
		fmt.Appendf([]byte{}, "%d", timestamp),
		[]byte(parsedUUID.String()),
		[]byte(base64.StdEncoding.EncodeToString(pc)),
	)

	if !ed25519.Verify(pc, message, signature) {
		return uuid.UUID{}, nil, nil, 0, errors.New("invalid signature")
	}

	return parsedUUID, pc, signature, timestamp, nil
}
