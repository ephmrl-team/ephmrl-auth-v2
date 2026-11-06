package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/ephmrl-team/ephmrl-auth-v2/internal/crypto"
	"github.com/google/uuid"
)

const signedMessageDomain = "ephmrl-auth:v2:ed25519"

type SignRequest struct {
	Method    string
	Path      string
	Query     string
	Host      string
	Type      string
	BodyHash  string
	Timestamp int64
	UUID      string
	PublicKey []byte
}

type VerifyRequest struct {
	Method   string
	Path     string
	Query    string
	Host     string
	Type     string
	BodyHash string
}

func NewRequest(method, path, requestType, bodyHash string, publicKey []byte) (*SignRequest, error) {
	requestID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	return &SignRequest{
		Method:    method,
		Path:      path,
		Type:      requestType,
		BodyHash:  bodyHash,
		Timestamp: time.Now().Unix(),
		UUID:      requestID.String(),
		PublicKey: publicKey,
	}, nil
}

func signedMessage(
	method string,
	path string,
	query string,
	host string,
	contentType string,
	bodyHash string,
	timestamp string,
	id string,
	publicKey []byte,
) []byte {
	return crypto.ConcatBytes(
		[]byte(signedMessageDomain),
		[]byte(method),
		[]byte(path),
		[]byte(query),
		[]byte(host),
		[]byte(contentType),
		[]byte(bodyHash),
		[]byte(timestamp),
		[]byte(id),
		[]byte(base64.StdEncoding.EncodeToString(publicKey)),
	)
}

func GenerateToken(edSecretKey []byte, request *SignRequest) (string, error) {
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

	if derivedPublicKey := ed25519.PrivateKey(edSecretKey).Public().(ed25519.PublicKey); !bytes.Equal(request.PublicKey, derivedPublicKey) {
		return "", errors.New("key pair mismatch")
	}

	message := signedMessage(
		request.Method,
		request.Path,
		request.Query,
		request.Host,
		request.Type,
		request.BodyHash,
		strconv.FormatInt(request.Timestamp, 10),
		id.String(),
		request.PublicKey,
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

	return base64.StdEncoding.EncodeToString(rawToken), nil
}

func DecodeToken(token string, request *VerifyRequest) (uuid.UUID, []byte, []byte, int64, error) {
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

	message := signedMessage(
		request.Method,
		request.Path,
		request.Query,
		request.Host,
		request.Type,
		request.BodyHash,
		strconv.FormatInt(timestamp, 10),
		parsedUUID.String(),
		pc,
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
