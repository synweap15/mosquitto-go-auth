package hashing

// Declare the valid encodings for validation.
const (
	UTF8   = "utf-8"
	Base64 = "base64"
)

var saltEncodings = map[string]struct{}{
	UTF8:   {},
	Base64: {},
}

type HashComparer interface {
	Hash(password string) (string, error)
	Compare(password, passwordHash string) bool
}

func preferredEncoding(saltEncoding string) string {
	preferredEncoding := Base64
	if _, ok := saltEncodings[saltEncoding]; ok {
		preferredEncoding = saltEncoding
	}
	return preferredEncoding
}
