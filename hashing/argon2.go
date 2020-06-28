package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"
)

type argon2Hasher struct {
	saltSize     int
	iterations   int
	saltEncoding string
	keyLen       int
	memory       uint32
	parallelism  uint8
}

func NewArgon2Hasher(saltSize int, iterations int, saltEncoding string, keylen int, memory uint32, parallelism uint8) HashComparer {
	return argon2Hasher{
		saltSize:     saltSize,
		iterations:   iterations,
		saltEncoding: preferredEncoding(saltEncoding),
		keyLen:       keylen,
		memory:       memory,
		parallelism:  parallelism,
	}
}

// adapted from https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
func (h argon2Hasher) Hash(password string) (string, error) {
	// Here commence the hackery - to prove the concept of generating and validating argon2id hashes with hard-coded params
	//saltSize = 16
	//var memory uint32 = 4096
	//iterations = 3
	//var parallelism uint8 = 2
	//keylen = 32
	// These hard-coded params above may need to be tuned - should they be passed in, configured as auth_opts or ...?
	// see https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4 for tuning considerations

	salt := make([]byte, h.saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return "", errors.Wrap(err, "read random bytes error")
	}

	return h.hashWithSalt(password, salt, h.memory, h.iterations, h.parallelism, h.keyLen), nil
}

// Compare checks that an argon2 generated password matches the password hash.
func (h argon2Hasher) Compare(password string, passwordHash string) bool {
	hashSplit := strings.Split(passwordHash, "$")

	if len(hashSplit) != 6 {
		log.Errorf("invalid hash supplied, expected 6 elements, got: %d", len(hashSplit))
		return false
	}

	version, err := strconv.ParseInt(hashSplit[2], 10, 32)
	if err != nil {
		log.Errorf("argon2 version parse error: %s", err)
		return false
	}

	if version != argon2.Version {
		log.Errorf("unknown argon2 version: %d", version)
		return false
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(hashSplit[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)

	var salt []byte
	switch h.saltEncoding {
	case UTF8:
		salt = []byte(hashSplit[3])
	default:
		salt, err = base64.StdEncoding.DecodeString(hashSplit[4])
		if err != nil {
			log.Errorf("base64 salt error: %w", err)
			return false
		}
	}

	extractedHash, err := base64.RawStdEncoding.DecodeString(hashSplit[5])
	if err != nil {
		log.Errorf("argon2 decoding error: %w", err)
		return false
	}

	keylen := uint32(len(extractedHash))
	newHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(keylen))

	if subtle.ConstantTimeCompare(newHash, extractedHash) == 1 {
		return true
	}

	return false
}

func (h argon2Hasher) hashWithSalt(password string, salt []byte, memory uint32, iterations int, parallelism uint8, keylen int) string {
	encodedSalt := salt
	if h.saltEncoding == Base64 {
		encodedSalt = []byte(base64.StdEncoding.EncodeToString(salt))
	}

	hashedPassword := argon2.IDKey([]byte(password), []byte(encodedSalt), uint32(iterations), memory, parallelism, uint32(keylen))
	b64Hash := base64.RawStdEncoding.EncodeToString(hashedPassword)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.memory, h.iterations, h.parallelism, encodedSalt, b64Hash)
}
