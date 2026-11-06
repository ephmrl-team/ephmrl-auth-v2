package main

import (
	"fmt"

	"github.com/ephmrl-team/ephmrl-auth-v2/pkg/auth"
	"github.com/ephmrl-team/ephmrl-auth-v2/pkg/identity"
)

func main() {
	identityKeys, secret, err := identity.Generate()
	if err != nil {
		panic(err)
	}

	request, err := auth.NewRequest(
		"DELETE",
		"/user",
		"application/json",
		"",
		identityKeys.PublicKeys.Ed25519,
	)
	if err != nil {
		panic(err)
	}

	request.Query = ""
	request.Host = "example.com"

	token, err := auth.GenerateToken(secret.Ed25519, request)
	if err != nil {
		panic(err)
	}

	fmt.Println(token)

	fmt.Println()

	verifyRequest := &auth.VerifyRequest{
		Method:   request.Method,
		Path:     request.Path,
		Query:    request.Query,
		Host:     request.Host,
		Type:     request.Type,
		BodyHash: request.BodyHash,
	}

	decodedUUID, publicKey, signature, decodedTimestamp, err := auth.DecodeToken(token, verifyRequest)
	if err != nil {
		panic(err)
	}

	fmt.Println("uuid", decodedUUID)
	fmt.Println("public key", publicKey)
	fmt.Println("signature", signature)
	fmt.Println("timestamp", decodedTimestamp)
}
