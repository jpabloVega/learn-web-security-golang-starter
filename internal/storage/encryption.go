package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	lastBytesPos := len(sealed) - 16
	cypherText := sealed[:lastBytesPos]
	authTag := sealed[lastBytesPos:]
	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: cypherText,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 || len(payload.AuthTag) != 16 {
		return []byte{}, errors.New("Invalid nonce or AuthTag")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return []byte{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	payload.Ciphertext = append(payload.Ciphertext, payload.AuthTag...)
	data, err := aead.Open(nil, payload.Nonce, payload.Ciphertext, nil)
	if err != nil {
		return []byte{}, err
	}
	return data, err
}
