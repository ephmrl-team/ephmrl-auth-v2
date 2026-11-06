package main

import (
	"fmt"

	"github.com/ephmrl-team/ephmrl-auth-v2/pkg/auth"
	"github.com/ephmrl-team/ephmrl-auth-v2/pkg/identity"
)

func main() {
	user, secret, err := identity.Generate()
	if err != nil {
		panic(err)
	}

	request, err := auth.NewRequest("DELETE", "/user", "application/json", "", user.PublicKeys.Ed25519)
	if err != nil {
		panic(err)
	}

	token, err := auth.GenerateToken(secret.Ed25519, request)
	if err != nil {
		panic(err)
	}

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
