// Package crypto provides AES-256-GCM encryption for sensitive fields stored in the database.
// The encryption key is loaded from the YAMA_FIELD_ENC_KEY environment variable (32 hex bytes = 64 hex chars).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

var errNoKey = errors.New("YAMA_FIELD_ENC_KEY not set or invalid (need 64 hex chars = 32 bytes)")

func loadKey() ([]byte, error) {
	raw := os.Getenv("YAMA_FIELD_ENC_KEY")
	if len(raw) != 64 {
		return nil, errNoKey
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext with AES-256-GCM. Returns hex(nonce+ciphertext+tag).
// Returns plaintext unchanged when no key is configured (dev mode).
func Encrypt(plaintext string) (string, error) {
	key, err := loadKey()
	if err != nil {
		return plaintext, nil // no-op in dev
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a value previously encrypted with Encrypt.
// Returns the value unchanged when it doesn't carry the "enc:" prefix (dev / legacy mode).
func Decrypt(value string) (string, error) {
	if len(value) < 4 || value[:4] != "enc:" {
		return value, nil // plaintext passthrough
	}
	key, err := loadKey()
	if err != nil {
		return "", fmt.Errorf("decrypt: key unavailable: %w", err)
	}
	data, err := hex.DecodeString(value[4:])
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}
