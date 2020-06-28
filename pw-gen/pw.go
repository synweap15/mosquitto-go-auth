package main

import (
	"flag"
	"fmt"

	"github.com/iegomez/mosquitto-go-auth/hashing"
)

func main() {

	const (
		sha256Size = 32
		sha512Size = 64
		argon2     = "argon2"
		pbkdf2     = "pbkdf2"
		bcrypt     = "bcrypt"
	)

	var hasher = flag.String("h", "pbkdf2", "hasher: pbkdf2, argon2 or bcrypt")
	var algorithm = flag.String("a", "sha512", "algorithm: sha256 or sha512")
	var iterations = flag.Int("i", 100000, "hash iterations")
	var password = flag.String("p", "", "password")
	var saltSize = flag.Int("s", 16, "salt size")
	var saltEncoding = flag.String("e", "base64", "salt encoding")
	var keylen = flag.Int("l", 0, "key length, recommend 32 for sha256 and 64 for sha512")
	var cost = flag.Int("c", 10, "bcrypt ost param")
	var memory = flag.Int("m", 4096, "memory for argon2 hash")
	var parallelism = flag.Int("pl", 2, "parallelism for argon2")

	flag.Parse()

	shaSize := *keylen

	if shaSize == 0 {
		switch *algorithm {
		case "sha265":
			shaSize = sha256Size
		case "sha512":
			shaSize = sha512Size
		default:
			fmt.Println("invalid password hash algorithm:", *algorithm)
			return
		}
	}

	var hashComparer hashing.HashComparer

	switch *hasher {
	case argon2:
		hashComparer = hashing.NewArgon2Hasher(*saltSize, *iterations, *saltEncoding, *keylen, uint32(*memory), uint8(*parallelism))
	case bcrypt:
		hashComparer = hashing.NewBcryptHashComparer(*cost)
	default:
		hashComparer = hashing.NewPBKDF2Hasher(*saltSize, *iterations, *algorithm, *saltEncoding, *keylen)
	}

	pwHash, err := hashComparer.Hash(*password)
	if err != nil {
		fmt.Printf("error: %s", err)
	} else {
		fmt.Println(pwHash)
	}

}
