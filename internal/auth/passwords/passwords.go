package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength   = 128
	MemoryKiB   = 19 * 1024
	KeyLength   = 32
	Iteration   = 2
	Parallelism = 1
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	passwordHash := argon2.IDKey([]byte(password), salt, Iteration, MemoryKiB, Parallelism, KeyLength)
	return encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		salt:        salt,
		derivedKey:  passwordHash,
		memoryKiB:   19 * 1024,
		iterations:  2,
		parallelism: 1,
	}), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if !ok {
		argon2Hash, valid := parseArgon2idHash(encodedHash)
		if !valid {
			return false
		}
		if argon2.Version != argon2Hash.version {
			return false
		}
		expectedArgon2Hash := argon2.IDKey([]byte(password), argon2Hash.salt, argon2Hash.iterations, argon2Hash.memoryKiB, argon2Hash.parallelism, uint32(len(argon2Hash.derivedKey)))
		return subtle.ConstantTimeCompare(expectedArgon2Hash, argon2Hash.derivedKey) == 1
	}
	candidateHash := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
}

func NeedsRehash(encodedHash string) bool {
	_, isLegacyHash := decodeLegacyHash(encodedHash)
	if isLegacyHash {
		return true
	}
	argon2Hash, valid := parseArgon2idHash(encodedHash)
	if valid {
		if argon2Hash.version != argon2.Version ||
			argon2Hash.memoryKiB != MemoryKiB ||
			argon2Hash.iterations != Iteration ||
			argon2Hash.parallelism != Parallelism ||
			len(argon2Hash.derivedKey) != KeyLength {
			return true
		}
	}
	return false
}
