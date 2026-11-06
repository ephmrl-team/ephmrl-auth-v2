package main

import (
	"fmt"
	"time"

	"github.com/ephmrl-team/ephmrl-auth-v2/pkg/auth"
	"github.com/ephmrl-team/ephmrl-auth-v2/pkg/identity"

	"github.com/google/uuid"
)

func main() {
	user, secret, err := identity.Generate()
	if err != nil {
		panic(err)
	}

	uuid, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}

	timestamp := time.Now().Unix()

	request := &auth.Request{
		Method:    "DELETE",
		Path:      "/user",
		Type:      "application/json",
		BodyHash:  "",
		Timestamp: timestamp,
		UUID:      uuid.String(),
		PublicKey: user.PublicKeys.Ed25519,
	}

	token := auth.GenerateToken(secret.Ed25519, request)

	fmt.Println(token)

	fmt.Println()

	uuid, publicKey, signature, timestamp, err := auth.DecodeToken(token, request)

	if err != nil {
		panic(err)
	}

	fmt.Println("uuid", uuid)
	fmt.Println("public key", publicKey)
	fmt.Println("signature", signature)
	fmt.Println("timestamp", timestamp)
}
